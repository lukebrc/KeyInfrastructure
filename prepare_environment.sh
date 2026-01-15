#!/bin/bash

if [ "$CA_PASWORD" == "" ]; then
  export CA_PASSWORD="ca_password"
fi

if [ "$DATABASE_URL" == "" ]; then
  DATABASE_URL="postgresql://postgres:infra_password@localhost:5432/keyinfrastructure"
fi

if [ "$JWT_SECRET" == "" ]; then
  JWT_SECRET="test_secret"
fi

cd backend

if [ ! -f .env ]; then
  echo "Creating backend .env"
  echo "CA_PASSWORD=$CA_PASSWORD" > .env
  echo "DATABASE_URL=$DATABASE_URL" >> .env
  echo "JWT_SECRET=$JWT_SECRET" >> .env
fi

if [ ! -d ca ]; then
  echo "Creating backend ca directory with CertificateAuthority"
  mkdir ca
  openssl genrsa -aes256 -passout pass:$CA_PASSWORD -out ca/ca.key 2048
  openssl req -x509 -new -nodes -key ca/ca.key -passin env:CA_PASSWORD -sha256 -days 3650 -out ca/ca.crt -subj "/CN=KeyInfrastructureCA"
fi

cd ../frontend

if [ ! -n .env ]; then
  echo "Creating frontend .env"
  cp .env.example .env
fi
