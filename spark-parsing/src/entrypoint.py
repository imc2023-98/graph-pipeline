#!/usr/bin/env python3

import datetime
import logging
import os.path
import pathlib
import shutil
import subprocess
import sys
import time

import click as click

SPARK_TMP_DIR = '/tmp/spark'


@click.command()
@click.option('--cleanup', type=bool, default=True)
@click.option('-r', '--requirements', type=click.Path(file_okay=True, dir_okay=False, exists=True))
@click.argument('pyspark-file', type=click.Path(file_okay=True, dir_okay=False, exists=True), required=False)
@click.option('--args', type=str)
def main(cleanup: bool, requirements: str, pyspark_file: str, args: list[str]):
    logging.basicConfig(level=logging.INFO)
    code = 0

    main_spark_dir = pathlib.Path(SPARK_TMP_DIR, 'main')
    main_log_dir = pathlib.Path(SPARK_TMP_DIR, 'logs')
    main_worker_dir = pathlib.Path(SPARK_TMP_DIR, 'worker')
    main_spark_dir.mkdir(parents=True, exist_ok=True)
    main_log_dir.mkdir(parents=True, exist_ok=True)
    main_worker_dir.mkdir(parents=True, exist_ok=True)

    try:
        if requirements is not None:
            subprocess.check_output(f'pip3 install -r {requirements}')
        args_list = [pyspark_file]
        if args is not None:
            args_list += args.split(' ')
        sub = subprocess.run(args_list)
        code = sub.returncode
    except Exception as e:
        logging.error(f'Error starting your application: {e}')
    finally:
        if cleanup:
            cleanup_spark_data(main_spark_dir, main_log_dir, main_worker_dir)

    if code != 0:
        logging.error(f'Application returned with error: {code}')
        sys.exit(code)


def cleanup_spark_data(main_spark_dir: str, main_log_dir: str, main_worker_dir: str):
    logging.info('Start Cleanup')

    main_dirs = [os.path.join(main_spark_dir, main_dir) for main_dir in os.listdir(main_spark_dir)]
    worker_dirs = [os.path.join(main_worker_dir, worker_dir) for worker_dir in os.listdir(main_worker_dir)]

    for to_be_deleted in main_dirs + worker_dirs:
        logging.info(f'Deleting {to_be_deleted}')
        shutil.rmtree(to_be_deleted, ignore_errors=True)

    for log_file_basename in os.listdir(main_log_dir):
        log_file = os.path.join(main_log_dir, log_file_basename)
        modified_time = os.path.getmtime(log_file)

        current_time = time.time()
        seven_days = datetime.timedelta(days=7).total_seconds()
        if modified_time < current_time - seven_days:
            logging.info(f'Deleting {log_file}')
            shutil.rmtree(log_file, ignore_errors=True)


if __name__ == '__main__':
    main()
