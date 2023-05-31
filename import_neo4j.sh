#!/usr/bin/env bash

input=$1

if [[ ! -d "$input" ]]; then
    echo "Please specify input directory."
    exit 1
fi

neo4j-admin database import full \
    --multiline-fields=true \
    --nodes=Certificate="$input/certs.csv" \
    --nodes=Domain="$input/domains.csv" \
    --nodes=IP="$input/ip_addresses.csv" \
    --relationships=ASSIGNED_TO="$input/assigned_to.csv" \
    --relationships=CONTAINS="$input/contains.csv" \
    --relationships=REDIRECTS="$input/redirects.csv" \
    --relationships=RESOLVES="$input/resolves.csv" \
    --relationships=RETURNS="$input/returns.csv" \
    --relationships=SERVES="$input/serves.csv" \
    --relationships=SUBDOMAIN_OF="$input/subdomain_of.csv" \
    --relationships=SUBJECT_TO="$input/subject_to.csv" \
    --trim-strings=true \
    --id-type=INTEGER \
    neo4j
