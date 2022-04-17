###
#
# DB for sclog
#
###

# Base image
FROM mysql:8-debian

# Container METADATA
LABEL maintainer "IB"

RUN apt update && apt install bash

# Overwrite global variables if needed
ENV LC_ALL=sl_SI.UTF-8
ENV MYSQL_ROOT_PASSWORD mysql

RUN sed -i -e 's/max_allowed_packet = 1M/max_allowed_packet = 100M/g' /etc/mysql/my.cnf
RUN sed -i -e '/\[mysqld\]/a\' -e 'lower_case_table_names = 1' /etc/mysql/my.cnf

# Copy SQL or BASH to the container to be executed by mariadb init script
ADD data/* /docker-entrypoint-initdb.d/ 
