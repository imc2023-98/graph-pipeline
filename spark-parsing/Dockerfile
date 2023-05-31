FROM debian:11

USER root

RUN apt-get update && apt-get install -y openjdk-17-jre-headless python3 python3-pip python3-click wget procps && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
ARG SPARK_FILE=spark-3.4.0-bin-hadoop3
RUN wget --quiet https://dlcdn.apache.org/spark/spark-3.4.0/${SPARK_FILE}.tgz && tar -xaf ${SPARK_FILE}.tgz && \
    rm ${SPARK_FILE}.tgz  && mv ${SPARK_FILE} spark

RUN python3 -m pip --quiet install --upgrade pip

COPY src/requirements.txt /opt
RUN pip3 --quiet install --no-cache-dir -r requirements.txt

RUN wget https://go.dev/dl/go1.20.4.linux-amd64.tar.gz && tar -C /usr/local -xzf go1.20.4.linux-amd64.tar.gz && rm go1.20.4.linux-amd64.tar.gz

ENV SPARK_HOME=/opt/spark
ENV PYTHONPATH=/opt/spark/python:/opt/spark/python/lib/py4j-0.10.9.3-src.zip
ENV PYSPARK_PYTHON=python3
ENV PATH=${SPARK_HOME}/bin:${SPARK_HOME}/sbin:${HADOOP_HOME}/bin::/usr/local/go/bin:${PATH}
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

COPY src/* /opt/
RUN mv spark-defaults.conf /opt/spark/conf/ && mv spark-env.sh /opt/spark/conf/ && mv log4j.properties /opt/spark/conf/  \
    && mkdir /app && ./entrypoint.py /opt/template.py && cd /opt && go build parse-certs.go

WORKDIR /app

ENTRYPOINT ["/opt/entrypoint.py"]
CMD /opt/template.py
