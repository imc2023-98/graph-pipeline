#!/usr/bin/env python3
import csv
import json
import logging
import os
import pathlib
import re
import shutil
import subprocess
from datetime import date
from functools import reduce
from urllib.parse import quote

import click
import pyspark.sql.functions as f
import tldextract
import validators as validators
from graphframes import *
from pyspark import SparkContext
from pyspark.sql import DataFrame, SparkSession, Window
from pyspark.sql.functions import col, lit
from pyspark.sql.types import *
from pyspark.sql.types import ArrayType, StringType

HOSTS_SCHEMA = 'id int NOT NULL, ip string NOT NULL, port int NOT NULL, server_name string,' \
    'synStart int, synEnd int, scanEnd int, protocol int, cipher string,' \
    'resultString string, error_data string, cert_id int, cert_hash string, pub_key_hash string, cert_valid int,' \
    'tls_alerts_send string, peer_certificates string, tls_alerts_received string, client_hello string'
CERTS_PARSED_SCHEMA = 'id int not null,system_cert_store int,sha1 string,sha256 string,subject string,issuer string,notBefore timestamp,notAfter timestamp,basicConstraints boolean,isCa boolean,sha256PubKey string,numAltNames int,altNames string'
IP_DOMAIN_SCHEMA = 'ip string, domain string'
CERT_PARSE_BIN = '/opt/parse-certs'


@click.command()
@click.option("--cache-dir", type=click.STRING, help="Cache Dir for intermediate results", required=True)
@click.option("--out", type=click.STRING, help="Out Dir", required=True)
@click.option('--parallelization', type=click.INT, help='Optimize Output for this parallelization', default=0)
@click.option('--output-type', type=click.Choice(['csv', 'parquet']), default='parquet', help='The output type')
@click.argument('inputs', nargs=-1, required=True)
def main(inputs: list[str], cache_dir: str, out: str, parallelization: int, output_type: str):

    logging.basicConfig(level=logging.INFO, format='%(asctime)s :: %(name)s :: %(levelname)-8s :: %(message)s')

    spark_config = (SparkSession.builder
        .appName("Parse TLS Graph")
        .master("local[*]")
        .config('spark.pyspark.python', 'python3')
        .config('spark.driver.memory', '8G')
    )

    out = pathlib.Path(os.path.abspath(out))
    inputs = [os.path.abspath(i) for i in inputs]

    spark = spark_config.getOrCreate()
    sc: SparkContext = spark.sparkContext

    sc.setLogLevel('ERROR')

    if parallelization == 0:
        parallelization = spark.sparkContext.defaultParallelism

    tmp_dir = pathlib.Path(cache_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    hosts_path = tmp_dir / 'hosts'
    http_path = tmp_dir / 'http'
    certs_parsed_path = tmp_dir / 'certs_parsed'
    certs_parsed_raw_path = tmp_dir / 'certs_parsed_raw'
    resolved_dn_ip_path = tmp_dir / 'dn_ip_resolved'

    goscanner_directories = set()
    ipdomains = set()
    all_dates = set()

    for scan_dir in inputs:
        scan_date_match = re.search(r"(\d{4})-(\d{2})-(\d{2})", scan_dir)
        if not scan_date_match:
            logging.error(f'No date found in {scan_dir}')
            continue

        scan_date = scan_date_match.group()
        all_dates.add(date.fromisoformat(scan_date))

        dir_content = os.listdir(scan_dir)
        for scan_file in dir_content:
            abs_scan_file = os.path.join(scan_dir, scan_file)
            if "hosts.csv" in scan_file:
                goscanner_directories.add((scan_dir, scan_date))
                break
            if ".ipdomain" in scan_file:
                ipdomains.add((abs_scan_file, scan_date))

    logging.info(f'Will process TLS scans: {list(goscanner_directories)}...')
    logging.info(f'Will process DNS scan files {list(ipdomains)}...')

    logging.info('Pre Process files')

    for scan_dir, scan_date in goscanner_directories:
        for source_csv, dd, target_path, i, ap in [
            (pathlib.Path(scan_dir, 'hosts.csv'), HOSTS_SCHEMA, hosts_path, scan_date,  f'source={os.path.basename(scan_dir)}'),
            (pathlib.Path(scan_dir, 'http.csv'), None, http_path, scan_date,  f'source={os.path.basename(scan_dir)}'),
        ]:
            process_csv(spark, parallelization, source_csv, dd, target_path, i, ap)

        process_certs(spark, certs_parsed_path, certs_parsed_raw_path, scan_date, scan_dir, parallelization)

    for scan_file, scan_date in ipdomains:
        pre_process_dns_job(scan_date, resolved_dn_ip_path, spark, scan_file, parallelization)

    logging.info(f'Finished pre processing files to {tmp_dir}')

    # Node Data
    hosts_df = spark.read.parquet(to_local_path(hosts_path)).withColumn('guid', f.concat(lit("h_"), col('id'), lit('_'), col('scan_date')))\
        .withColumn('server_name', f.regexp_replace('server_name', r'\.$', ''))

    certs_df = spark.read.parquet(to_local_path(certs_parsed_path))\
        .withColumn("guid", f.concat(lit("c_"), col("sha256"))) \
        .where(f.length('sha256') == 64)  # Sanity check for correctly parsed certs
    http_df = spark.read.parquet(to_local_path(http_path))

    # Edges (include the scan time)
    dn_ip_df = spark.read.parquet(to_local_path(resolved_dn_ip_path)) \
        .select(f.regexp_replace('domain', r'\.$', '').alias('domain'), 'ip', 'scan_date')

    cert_san = certs_df.where("altNames is not null") \
        .select('guid', f.explode('altNames').alias('alt_name')) \
        .withColumn('is_ip', is_valid_ip('alt_name')) \
        .select('guid', f.when(~col('is_ip'), col('alt_name')).alias('domain_name'), f.when(col('is_ip'), col('alt_name')).alias('ip'))

    ip_returns_cert = hosts_df.select(f.concat(lit("ip_"), col("ip")).alias('from'),
                  f.concat(lit("c_"), col("cert_hash")).alias('to'), (col('cert_valid') == 1).alias('valid'), col('server_name').alias('sni'), 'scan_date')

    domain_observed_on_ip = hosts_df.select(f.concat(lit("d_"), col('server_name')).alias('from'),
                                            f.concat(lit("ip_"), col("ip")).alias('to'),
                                            (col('cert_valid') == 1).alias('valid'), 'scan_date')

    domains_raw = cert_san.select('domain_name') \
        .union(hosts_df.select('server_name')) \
        .union(dn_ip_df.select('domain')) \
        .union(http_df.select(extract_location('Location')))\
        .where('domain_name is not null')

    logging.info(f'Exploding domains')

    domain_raw_exploded = domains_raw\
        .withColumn('domains', explode_domains('domain_name'))\
        .select(f.explode('domains').alias('domain_name'))\
        .where('domain_name is not null')\
        .withColumn('guid', f.concat(f.lit('d_'), col('domain_name'))).distinct()

    domains_all_exploded = checkpoint_df(spark, 'domains_df', tmp_dir, parallelization, domain_raw_exploded)

    logging.info(f'Finished exploding domains. Test: {domains_all_exploded.first()}')

    ips = hosts_df.select('ip')\
        .union(dn_ip_df.select('ip'))\
        .union(cert_san.select('ip')) \
        .where(is_valid_ip('ip')) \
        .where('ip is not null').withColumn('guid', f.concat(lit("ip_"), col("ip")))

    redirects = http_df.join(hosts_df, on=['scan_date', 'id']) \
        .select(col('server_name').alias('from'), extract_location('Location').alias('to'),
                col('Location').alias('location'), (col('cert_valid') == 1).alias('valid'), 'scan_date') \
        .where(col('from').isNotNull() & col('to').isNotNull()) \
        .select(f.concat(lit('d_'), col('from')).alias('from'), f.concat(lit('d_'), col('to')).alias('to'),
                sanitize_url('location').alias('location'), 'valid', 'scan_date')

    logging.info(f'Generating unique IDs')

    # id_mapping is used to get globally unique ids over all data. It maps scan-wide ids (e.g. cert_ID) to the global id
    df_all_guid_raw = (certs_df.select('guid').distinct()
                       .union(domains_all_exploded.select('guid'))
                       .union(ips.select('guid').distinct()))

    window_id = Window.orderBy(col('id_l').asc_nulls_first())
    df_all_guid_raw = df_all_guid_raw \
        .withColumn('id_l', f.monotonically_increasing_id()) \
        .withColumn('id', f.row_number().over(window_id) - lit(1)).drop('id_l')

    id_mapping = checkpoint_df(
        spark,
        'id_mapping',
        tmp_dir,
        parallelization,
        df_all_guid_raw,
        buckets='guid'
    )

    logging.info(f'Storing Relations')

    returns_df = save_rel(spark, out, "returns", id_mapping, ip_returns_cert, parallelization, output_type)

    dn_ip_df_rel = dn_ip_df.withColumn('from', f.concat(lit('d_'), col('domain'))).withColumn('to', f.concat(lit('ip_'),
                                                                                                             col('ip')))
    resolves_df = save_rel(spark, out, "resolves", id_mapping,
             domain_observed_on_ip.unionByName(dn_ip_df_rel, allowMissingColumns=True)
             .groupBy('from', 'to', 'scan_date').agg((f.max('valid') == 1).alias('valid')), parallelization, output_type)

    contains_df = save_rel(spark, out, "contains", id_mapping,
             cert_san.select(col('guid').alias('from'), f.concat(lit('d_'), col('domain_name')).alias('to'))
             .union(
                 cert_san.select(col('guid').alias('from'), f.concat(lit('ip_'), col('ip')).alias('to'))),
             parallelization, output_type)

    redirects_df = save_rel(spark, out, "redirects", id_mapping, redirects, parallelization, output_type)

    subdomain_of_df = save_rel(spark, out, 'subdomain_of', id_mapping, domains_all_exploded
             .select(col('guid').alias('from'), explode_domains('domain_name').getItem(1).alias('to'))
             .where('to is not null').withColumn('to', f.concat(lit('d_'), col('to'))), parallelization, output_type)

    subject_to_df = contains_df.join(returns_df.where('valid').select(col('dst').alias('src')), on='src', how='left_semi')\
        .select(col('dst').alias('src'), col('src').alias('dst'))

    save_rel_simple(out, 'subject_to', subject_to_df, parallelization, output_type)

    assigned_to_df = get_valid_reversed_rel(returns_df)
    save_rel_simple(out, 'assigned_to', assigned_to_df, parallelization, output_type)
    serves_df = get_valid_reversed_rel(resolves_df)
    save_rel_simple(out, 'serves', serves_df, parallelization, output_type)

    # Compute graph metrics
    logging.info(f'Computing Metrics')
    all_edges = [returns_df, resolves_df, contains_df, redirects_df, subdomain_of_df, assigned_to_df, subject_to_df, serves_df]
    edges_df = reduce(lambda x,y: x.union(y), [ df.select('src', 'dst') for df in all_edges] )

    g = GraphFrame(id_mapping, edges_df)
    in_df = checkpoint_df(spark, 'in_degree', tmp_dir, parallelization, g.inDegrees, buckets='id')
    logging.info(f'inDegree done')
    out_df = checkpoint_df(spark, 'out_degree', tmp_dir, parallelization, g.outDegrees, buckets='id')
    logging.info(f'outDegree done')

    # Save Vertices
    certs_out = ['subject', 'issuer', 'notBefore', 'notAfter', 'numAltNames']
    certs_out = list(map(lambda x: f.max(x).alias(x), certs_out))

    save_vertex(spark, out, 'certs', id_mapping, certs_df.groupBy('guid', 'sha1', 'sha256')
                .agg(*certs_out), parallelization, in_df, out_df, out_type=output_type)
    save_vertex(spark, out, 'domains', id_mapping, domains_all_exploded, parallelization, in_df, out_df, out_type=output_type)
    save_vertex(spark, out, 'ip_addresses', id_mapping, ips, parallelization, in_df, out_df, out_type=output_type)
    logging.info(f'Done')


def pre_process_dns_job(scan_date, resolved_dn_ip_path, spark, domain_file: str, parallelization):
    name = 'type=A'
    if 'AAAA' in domain_file:
        name = 'type=AAAA'
    df_path = os.path.join(resolved_dn_ip_path, f'scan_date={scan_date}', name)

    if should_save(df_path):
        save_df(df_path, parallelization, spark.read.csv(to_local_path(domain_file), header=False, inferSchema=False, enforceSchema=False, escape='"', quote='"', schema=IP_DOMAIN_SCHEMA))


def process_csv(spark, parallelization, source_csv, dd, target_path, i, ap):
    name = f'scan_date={i}'
    df_path = pathlib.Path(target_path, name, ap)
    try:
        if should_save(df_path):
            df_tmp = load_csv(spark, source_csv, parallelization, schema=dd)
            save_df(df_path, parallelization, df_tmp)
        return os.path.join(target_path, name)
    except Exception as err:
        logging.exception('Could not process csv', exc_info=err)


def process_certs(spark: SparkSession, certs_parsed_path: pathlib.Path, certs_parsed_raw_path: pathlib.Path, scan_date: str, scan_dir: str, parallelization: int):
    certs_file = pathlib.Path(scan_dir, 'certs.csv')

    name = f'scan_date={scan_date}'
    df_path = certs_parsed_path / name / f'source={os.path.basename(scan_dir)}'
    if not should_save(df_path):
        return
    if not certs_file.exists():
        raise Exception(f'No Certs found under {f}')

    df_raw_path = certs_parsed_raw_path / name / f'source={os.path.basename(scan_dir)}'
    df_raw_csv_path = df_raw_path / 'certs.csv'
    if should_save(df_raw_path):
        df_raw_path.mkdir(exist_ok=True, parents=True)
        subprocess.check_output(f'{CERT_PARSE_BIN} --input {certs_file} --output {df_raw_csv_path}', shell=True, text=True)
        (df_raw_path / '_SUCCESS').write_text('')

    df_tmp = load_csv(spark, df_raw_csv_path, parallelization, schema=CERTS_PARSED_SCHEMA)\
        .withColumn('altNames', f.from_json('altNames', schema=ArrayType(StringType())))

    save_df(df_path, parallelization, df_tmp)


@f.udf(returnType=StringType())
def extract_location(location: str):
    if location is None:
        return None
    try:
        extracted = tldextract.extract(location)
        fqdn = extracted.fqdn
        if fqdn != '' and validators.domain(fqdn):
            return fqdn
    except:
        return None


# Copy from validators.ipv4 because of strange pickle errors
def ipv4(value):
    groups = value.split('.')
    if len(groups) != 4 or any(not x.isdigit() for x in groups):
        return False
    return all(0 <= int(part) < 256 for part in groups)


# Copy from validators.ipv6 because of strange pickle errors
def ipv6(value):
    ipv6_groups = value.split(':')
    if len(ipv6_groups) == 1:
        return False
    ipv4_groups = ipv6_groups[-1].split('.')

    if len(ipv4_groups) > 1:
        if not ipv4(ipv6_groups[-1]):
            return False
        ipv6_groups = ipv6_groups[:-1]
    else:
        ipv4_groups = []

    max_groups = 6 if ipv4_groups else 8
    if len(ipv6_groups) > max_groups:
        return False

    count_blank = 0
    for part in ipv6_groups:
        if not part:
            count_blank += 1
            continue
        try:
            num = int(part, 16)
        except ValueError:
            return False
        else:
            if not 0 <= num <= 65536:
                return False

    if count_blank < 2:
        return True
    elif count_blank == 2 and not ipv6_groups[0] and not ipv6_groups[1]:
        return True
    return False


@f.udf(returnType=BooleanType())
def is_valid_ip(ip: str):
    return ip is not None and (ipv4(ip) or ipv6(ip))


def to_local_path(f):
    return f'{f}'


def save_vertex(spark: SparkSession, output_dir: str, name: str, id_mapping: DataFrame, df: DataFrame, parallelization,
                in_df, out_df, out_type='csv'):
    out_path_normal = pathlib.Path(output_dir, name)
    if should_save(out_path_normal):
        shutil.rmtree(out_path_normal, ignore_errors=True)
        out_path = to_local_path(out_path_normal) + '.' + out_type
        columns = ['id'] + df.columns
        columns.remove('guid')
        df_out = df.distinct().join(id_mapping, on='guid').select(*columns)\
            .join(in_df, on='id', how='left_outer')\
            .join(out_df, on='id', how='left_outer')

        if out_type == 'csv':
            save_df_csv(df_out, out_path)
        elif out_type == 'parquet':
            df_out.repartitionByRange(parallelization, 'id').write.parquet(out_path)
        else:
            raise Exception(f'Unknown type {out_type}')
        logging.info(f"Wrote {name} as {out_type} to disk!")
    else:
        logging.info(f"Skipping vertex {name}")


def save_rel(spark: SparkSession, output_dir: str, name: str, id_mapping: DataFrame, df: DataFrame, parallelization,
             out_type='csv'):
    out_path_normal = pathlib.Path(output_dir, name)
    out_path = to_local_path(out_path_normal) + '.' + out_type

    id_src_mapping = id_mapping.withColumnRenamed('guid', 'from').withColumnRenamed('id', 'src')
    id_dst_mapping = id_mapping.withColumnRenamed('guid', 'to').withColumnRenamed('id', 'dst')
    columns = ['src', 'dst'] + df.columns
    columns.remove('from')
    columns.remove('to')

    df_out = df.join(id_src_mapping, on='from').join(id_dst_mapping, on='to')

    if 'scan_date' in columns:
        columns.remove('scan_date')
        agg_columns = [f.sort_array(f.collect_set('scan_date')).alias('scan_dates')]
        if 'sni' in columns:
            columns.remove('sni')
            agg_columns.append(f.sort_array(f.collect_set('sni')).alias('server_name_indicators'))
        if 'valid' in columns:
            columns.remove('valid')
            agg_columns.append(f.max('valid').alias('valid'))
        if 'location' in columns:
            columns.remove('location')
            agg_columns.append(f.sort_array(f.collect_set('location')).alias('locations'))
        df_out = df_out.groupBy(*columns).agg(*agg_columns)
    else:
        df_out = df_out.select(*columns).distinct()

    if should_save(out_path_normal):
        shutil.rmtree(out_path_normal, ignore_errors=True)

        if out_type == 'csv':
            save_df_csv(df_out, out_path)
        elif out_type == 'parquet':
            df_out.repartitionByRange(parallelization, "src", "dst").write.parquet(out_path)
        else:
            raise Exception(f'Unknown type {out_type}')

        logging.info(f"Wrote rel {name} as {out_type} to disk!")
    else:
        logging.info(f"Skipping rel {name}")
    if out_type == 'csv':
        csv_columns = [ f'{c} int' if c in ['src', 'dst'] else f'{c} boolean' if c == 'valid' else f'{c} string' for c in df_out.columns]
        return spark.read.csv(out_path, schema=','.join(csv_columns), header=False, enforceSchema=False)
    else:
        return spark.read.parquet(out_path)


def save_rel_simple(output_dir: str, name: str, df: DataFrame, parallelization, out_type='csv'):
    out_path = pathlib.Path(output_dir, name + '.' + out_type)
    out_path_str = to_local_path(out_path)

    if should_save(out_path):
        shutil.rmtree(out_path, ignore_errors=True)
        if out_type == 'csv':
            save_df_csv(df, out_path)
        elif out_type == 'parquet':
            df.repartitionByRange(parallelization, "src", "dst").write.parquet(out_path_str)
        else:
            raise Exception(f'Unknown type {out_type}')

        logging.info(f"Wrote rel {name} as {out_type} to disk!")
    else:
        logging.info(f"Skipping rel {name}")


def to_neo4j_header(header):
    for h in header:
        if h == 'id':
            yield ':ID'
        elif h == 'src':
            yield ':START_ID'
        elif h == 'dst':
            yield ':END_ID'
        elif h == 'scan_date':
            yield 'scan_date:date'
        elif h == 'scan_dates':
            yield 'scan_date:date[]'
        elif h in ['server_name_indicators', 'locations']:
            yield f'{h}:string[]'
        elif h in ['basicConstraints', 'isCa', 'valid']:
            yield f'{h}:boolean'
        elif h in ['inDegree', 'outDegree', 'numAltNames']:
            yield f'{h}:int'
        else:
            yield h


def save_df_csv(df: DataFrame, to_file: pathlib.Path):
    if 'scan_dates' in df.columns:
        df = df.withColumn('scan_dates', f.concat_ws(';', f.col('scan_dates')))
    if 'server_name_indicators' in df.columns:
        df = df.withColumn('server_name_indicators', f.concat_ws(';', f.col('server_name_indicators')))
    if 'locations' in df.columns:
        df = df.withColumn('locations', f.concat_ws(';', f.col('locations')))

    shutil.rmtree(f'{to_file}.tmp', ignore_errors=True)
    df.write.csv(f'{to_file}.tmp', header=False, escape='"', quote='"')
    csv_header = list(to_neo4j_header(df.columns))
    with pathlib.Path(to_file).open(mode='w') as output_file:
        csv.writer(output_file).writerow(csv_header)

    subprocess.check_output(f'cat {to_file}.tmp/part* >> {to_file}', shell=True, text=True)
    shutil.rmtree(f'{to_file}.tmp')


@f.udf(returnType=ArrayType(StringType()))
def explode_domains(domain: str):
    if domain is None:
        return None
    try:
        if validators.domain(domain) or validators.domain(domain.replace('*.', '')):
            extracted = tldextract.extract(domain, include_psl_private_domains=True)
            d_list = extracted.subdomain.split(".")
            d_list.append(extracted.domain)
            d_list.append(extracted.suffix)
            d_t_list = [e for e in d_list if e]
            r_list = [".".join(d_t_list[i:]) for i in range(len(d_t_list) - 1)]
            return r_list
    except:
        return None


def get_valid_reversed_rel(df: DataFrame):
    select_cols = [col('dst').alias('src'), col('src').alias('dst')]
    if 'scan_dates' in df.columns:
        select_cols.append(col('scan_dates'))
    return df.where('valid').select(*select_cols)


def load_csv(spark: SparkSession, file: pathlib.Path, parallelization, schema=None):
    if not file.exists():
        raise FileNotFoundError(f'Could not find file {file}')
    df = spark.read.csv(to_local_path(file), multiLine=True, header=True, inferSchema=False, enforceSchema=False, escape='"', quote='"', schema=schema, mode='DROPMALFORMED')
    return df.repartition(parallelization)


def checkpoint_df(spark: SparkSession, name: str, storage_dir: str, parallelization: int,
                  df: DataFrame, partitions=None, buckets=None) -> DataFrame:
    df_file = pathlib.Path(storage_dir, name)

    if not should_save(df_file):
        logging.debug(f'Read from last run: {df_file}')
        return spark.read.parquet(to_local_path(df_file))
    if buckets is None:
        df = df.repartition(parallelization)
    else:
        df = df.repartitionByRange(parallelization, buckets)
    writer = df.write.format('parquet').option('path', to_local_path(df_file)).mode('overwrite')
    if partitions is not None:
        writer = writer.partitionBy(partitions)
    writer.save()
    return spark.read.parquet(to_local_path(df_file))


@f.udf(returnType=StringType())
def sanitize_url(url: str):
    if url is None:
        return ''
    return quote(url, safe=':/?=&')


def save_df(df_path: pathlib.Path, parallelization: int, df: DataFrame, partitions=None, repatition_range=None):
    df = df.repartition(parallelization)
    writer = df.write
    if partitions is not None:
        writer = writer.partitionBy(partitions)
    shutil.rmtree(df_path, ignore_errors=True)
    writer.parquet(to_local_path(df_path))


def should_save(out_path) -> bool:
    out_success = pathlib.Path(out_path, '_SUCCESS')
    return not out_success.exists()


if __name__ == "__main__":
    main()
