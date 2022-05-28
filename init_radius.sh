#!/bin/bash

sudo cp ca/private/server.key.pem /etc/ssl/private/server.key.pem
sudo cp ca/certs/server.pem /etc/ssl/certs/server.pem
sudo cp ca/cacert.pem /etc/ssl/certs/cacert.pem

sudo chown freerad:freerad /etc/ssl/private/server.key.pem
sudo chown freerad:freerad /etc/ssl/certs/server.pem
sudo chown freerad:freerad /etc/ssl/certs/cacert.pem 
