WePN
================

WePN is a framework created to enable everybody to protect its privacy.
Get a cloud server (cheap these days), install wepn, and you're all set to protect and own your data.

## Principle
WePN is mainly a VPN system, where the server is acting as a proxy to the Internet. The traffic can therefore be analyzed, blocked, redirected.

The server is composed of multiple docker services. The main one is the system itself, with an OpenVPN server, a Bind server (DNS), a monitor gathering the traffic and pushing it in a PostgreSQL database and an Nginx server to redirect http.
The others are applications, which can be installed by the users.

An application is a docker container which can receive and send traffic, under restrictions planned by the users. A default app is present on WePN, the admin interface, where the users can monitor the network and their traffic.

## Basic install

Just clone this repository, install docker and docker-compose for your OS, and run :

```shell
docker-compose build
docker-compose run
```

## Applications

### Docker container

An 

### Domains

To communicate simply with the application, a domain is assigned to each application. The main server is resolved by X.wepn.social, where X has to be chosen at initialization. In order to go public, you have to check that the domain is not already taken.
A new application is assigned Y.X.wepn.social where Y is defined in the application configuration. Every domain is pointing to a unique ip, a reverse proxy (nginx) is in charge of redirecting the requests.
