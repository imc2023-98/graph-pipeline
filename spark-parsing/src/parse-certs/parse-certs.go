package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	input := flag.String("input", "", "input csv [.zst] with certificates in cert column")
	output := flag.String("output", "", "Output [.zst] File")
	noHeader := flag.Bool("no-header", false, "Disable csv header")
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if *input == "" {
		log.Fatal().Msg("Pleas specify input")
	}

	parseCerts(*input, *output, !*noHeader)
}

func parseCerts(input string, output string, showHeader bool) {

	outputChan := make(chan []string, 1000)

	var inputFile io.ReadCloser
	inputFile, _ = os.Open(input)
	header, err := csv.NewReader(inputFile).Read()
	if err != nil {
		log.Fatal().Err(err).Msg("Could not read from certs csv")
	}
	inputFile.Close()

	var outputStream io.Writer
	if output == "-" || output == "" {
		outputStream = os.Stdout
	} else {
		outputFile, err := os.Create(output)
		defer outputFile.Close()
		outputStream = outputFile
		if err != nil {
			log.Fatal().Err(err).Msg("Could not create output file")
		}
	}

	csvWriter := csv.NewWriter(outputStream)

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		var outHeader []string
		for _, c := range header {
			if c != "cert" {
				outHeader = append(outHeader, c)
			}
		}
		outHeader = append(outHeader,
			"sha1",
			"sha256",
			"subject",
			"issuer",
			"notBefore",
			"notAfter",
			"basicConstraints",
			"isCa",
			"sha256PubKey",
			"numAltNames",
			"altNames",
		)
		if showHeader {
			err := csvWriter.Write(outHeader)
			if err != nil {
				log.Fatal().Err(err).Msg("Could not write to output")
			}
		}
		numCerts := 0
		for o := range outputChan {
			numCerts++
			err := csvWriter.Write(o)
			if err != nil {
				log.Fatal().Err(err).Msg("Could not write to output")
			}
		}
		csvWriter.Flush()
		log.Info().Int("NumCerts", numCerts).Msg("Written all Certificates")
		wg.Done()
	}()

	numCerts := 0

	parseFunc := func(certRow []string, certColumn int, rootStoreColumn int) {
		var out []string
		cert := parseCert(certRow[certColumn])
		if cert != nil {
			for i, c := range certRow {
				if i != certColumn {
					out = append(out, c)
				}
			}
			dnsDames := ""
			names, err := json.Marshal(cert.DNSNames)
			if err != nil {
				log.Error().Err(err).Msg("Error parsing dns names")
			} else {
				dnsDames = string(names)
			}

			out = append(out,
				hex.EncodeToString(GetSHA1(cert.Raw)),
				hex.EncodeToString(GetSHA256(cert.Raw)),
				strings.ReplaceAll(cert.Subject.String(), "\r", "\\r"),
				strings.ReplaceAll(cert.Issuer.String(), "\r", "\\r"),
				cert.NotBefore.Format(time.RFC3339),
				cert.NotAfter.Format(time.RFC3339),
				strconv.FormatBool(cert.BasicConstraintsValid),
				strconv.FormatBool(cert.IsCA),
				hex.EncodeToString(GetSHA256(cert.RawSubjectPublicKeyInfo)),
				strconv.Itoa(len(cert.DNSNames)),
				dnsDames,
			)
			outputChan <- out
			numCerts++
		} else {
			log.Debug().Msg("Cert was null")
		}
	}

	processCerts(input, "cert", "system_cert_store", parseFunc)
	log.Info().Int("Num Certs", numCerts).Msg("Processed Certs")
	close(outputChan)

	wg.Wait()
}

type certProcessor func([]string, int, int)

func processCerts(input string, column string, root_store_column string, runOnCerts certProcessor) {
	var certsFile io.ReadCloser
	certsFile, err := os.Open(input)
	if err != nil {
		log.Fatal().Err(err).Msg("Could not open certs file")
	}
	defer certsFile.Close()

	certs := make(chan []string, 1000)

	csvReader := csv.NewReader(certsFile)

	header := ParseHeader(csvReader)
	if _, present := header[column]; !present {
		log.Fatal().Str("column", column).Msg("No cert column in csv")
	}
	if _, present := header[root_store_column]; !present && root_store_column != "" {
		log.Fatal().Str("column", column).Msg("No cert column in csv")
	}
	certColumn := header[column]
	rootStoreColumn := -1
	if root_store_column != "" {
		rootStoreColumn = header[root_store_column]
	}

	wg := sync.WaitGroup{}

	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			for certRow := range certs {
				runOnCerts(certRow, certColumn, rootStoreColumn)
			}
			wg.Done()
		}()
	}

	numCerts := 0

	for line, err := csvReader.Read(); err != io.EOF; line, err = csvReader.Read() {
		certs <- line
		numCerts++
	}
	log.Info().Str("Input", input).Int("NumCerts", numCerts).Msg("Read Certificates")
	close(certs)
	wg.Wait()
}

func parseCert(certString string) (cert *x509.Certificate) {
	block, _ := pem.Decode([]byte(certString))
	if block == nil {
		log.Error().Str("id", certString).Msg("Failed to decode certificate")
		return
	}
	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		log.Error().Msg("No CERTIFICATE block")
		return
	}
	var err error
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		// log.Error().Err(err).Str("id", certString).Msg("Failed to parse certificate")
		return nil
	}
	return
}

func ParseHeader(reader *csv.Reader) map[string]int {
	record, err := reader.Read()
	if err != nil {
		log.Fatal().Err(err).Msg("no csv header given")
	}

	if record == nil || len(record) == 0 {
		log.Fatal().Msg("no csv header given")
	}

	result := make(map[string]int)
	for i, h := range record {
		result[h] = i
	}
	return result
}

func GetSHA256(input []byte) []byte {
	hash := sha256.Sum256(input)
	return hash[:]
}

func GetSHA1(input []byte) []byte {
	hash := sha1.Sum(input)
	return hash[:]
}
