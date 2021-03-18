# Auth service

## Presentation

Authentification service serves as an authorization provider for a micro service based system.
It works using stateless applications. Authentication / authorization is based on Json Web Tokens (JWT).

## Technical stack

This first service is built with OCaml. The stack relies on:
- [Yojson](https://ocaml-community.github.io/yojson/yojson/Yojson/index.html): functions for reading and writing JSON data
- [Lwt](https://ocsigen.org/lwt/5.3.0/manual/manual): promises library
- [Opium](https://rgrinberg.github.io/opium/opium/index.html#overview): middleware based web framework - _Sinatra/Expressjs like_
- [Catqi](https://paurkedal.github.io/ocaml-caqti/index.html): OCaml connector API for relational databases
- PostgreSQL: relational database
- [Postman](https://www.postman.com/downloads/) : to test the API

## Development

- install: `esy install`
- build: `esy build`
- start: `esy start`