#!/bin/bash
while true; do echo -e "HTTP/1.1 200 OK\n\n" | nc -l -p 8443; done
