# HOT CHEESE
## keeps your private keys warm and safe and still easily, but securely accessible

APP on my mac, which has encrypted keys. 
keys are stored somehwere in some folder

WHERE IS THE ENCRYPTION KEY?

-> KeyChainApp


WHEN YOU RUN IT IT RUNS A LOCAL SERVER HTTPS

say you want to deliver a private key to a service in the cloud, anywhere,
when you restart the service, you will need to somehow forward the key to the service

The idea is that in the moment that you restart the service you can have a script, which forwards your local https server
to the target machine and at that moment only the program that you are trying to run will be able to request a key.
When a key is requested the app with ask with touch id for confirmation to access decryption key, decypt the key and send it over https.

Additional goal:
- not have anything left in memory: no encryption keys or private keys


API:
- /generate/<name>
- /read/<name> (upon touch id verification + permission to access target decryption key in keychain, will return the relevant key)

What about backup?
- encryption key -> you back it only once
- but with the private keys you will have to backup every time you make new ones, which is imperfect


## yes
requesting machine generates a single use encryption to encrypt the secret in transit to it