#!/usr/bin/env python3

import click
from pyspark import SparkContext
from pyspark.sql import SparkSession


@click.command()
def main():
    spark_config = SparkSession.builder \
        .appName("Template application") \
        .master('local[*]')

    spark: SparkSession = spark_config.getOrCreate()
    sc: SparkContext = spark.sparkContext

    spark.stop()


if __name__ == '__main__':
    main()
