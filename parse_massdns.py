#!/usr/bin/env python3

import csv
import io
import itertools
import json
import logging
import os.path
import sys
import pathlib
from typing import List

import click
from contextlib import ExitStack


@click.command()
@click.option('--output', type=click.Path(file_okay=False, dir_okay=True), required=True)
@click.argument('input-file', type=click.File('r'), default=sys.stdin)
def extract_domains(output: str, input_file: io.TextIOWrapper):
    types = [('A', 'resolved-A.ipdomain'), ('AAAA', 'resolved-AAAA.ipdomain') ]
    pathlib.Path(output).mkdir()
    logging.basicConfig(filename=os.path.join(output, 'massdns_parse.log'))
    with ExitStack() as stack:
        out_files = {fname[0]: csv.writer(stack.enter_context(open(os.path.join(output, fname[1]), 'w'))) for fname in
                     types}
        for line in input_file:
            try:
                parsed = json.loads(line)
                parent_name = parsed['name']
                if 'data' in parsed:
                    data = parsed['data']
                    if 'answers' in data:
                        answers = data['answers']
                        parse_records(out_files, answers, parent_name)
            except Exception as e:
                logging.exception(f'Exception occurred at {line}', exc_info=e)


def follow_cnames(name, cname, answers, out_files, stack=[]):
    if cname not in stack:
        stack.append(cname)
        for answer in answers:
            sub_name = answer['name'].rstrip('. ')
            if cname == sub_name:
                data = answer['data'].rstrip('. ')
                t = answer['type']
                if t in ['A', 'AAAA']:
                    out_files[t].writerow([data, name])
                elif t == 'CNAME':
                    follow_cnames(name, data, answers, out_files, stack=stack + [])
                else:
                    logging.error(f'Unknown type for {name}: {answer}')


def parse_records(out_files: List[csv.writer], answers, parent_name: str):
    for answer in answers:
        t = answer['type']
        data = answer['data'].rstrip('. ')
        name = answer['name'].rstrip('. ')
        if t in ['A', 'AAAA']:
            out_files[t].writerow([data, name])
        elif t == 'CNAME':
            follow_cnames(name, data, answers, out_files, stack=[name])
        else:
            logging.error(f'Unknown type for {name}: {answer}')


if __name__ == '__main__':
    extract_domains()
