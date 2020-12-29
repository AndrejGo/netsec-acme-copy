# netsec-acme-copy
  Copy of the ACME client assignment for the Network Security course, autumn semester 2020.

## 1. Install pebble
https://github.com/letsencrypt/pebble

## 2. Run the pebble server
cd into the `project` directory and execute `./runPebble`. This will start
a local Pebble ACME server as configured in `pebble-config.json`.

## 3. Compile and run the ACME client
Open a separate terminal. cd into the `project` directory and run `./compile`
to build the ACME client. Then execute `./runClient <option>` where 
<i>option</i> is either 1 for a DNS challenge or 2 for an HTTP challenge.

After the ACME client is done, it will save the key and certificate into
`server.key` and `server.cert` respectively.

## 4. Shutting down the client
The client should be shut down with a GET request to
`http://localhost:5003/shutdown` after which the files `server.key` and
`server.cert` will be deleted.
