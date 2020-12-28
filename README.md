# netsec-acme-copy
  Copy of the ACME client assignment for the Network Security course, autumn semester 2020.

## 1. Install pebble
https://github.com/letsencrypt/pebble

## 2. Run the pebble server
cd into the `project` directory and execute `./runPebble`. This will start
a local Pebble ACME server as configured in `pebble-config.json`.

## 3. Compile and run the ACME client
Open a separate terminal. cd into the `project` directory and run `./compile`
to build the ACME client. Then execute `./runClient`.
