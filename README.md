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

An application is a docker container running on the server, or on any hosting machine provided by the client. It is part of the VPN, so it has a virtual IP as the users.

### Restrictions

The users want their application safe, and privacy friendly. They don't want it to send data to the Internet (that's actually the main reason why they installed WePN).

Restrictions are managed via iptables on the system container.

Users can manage them with a UI on the admin interface.

### Agregation

Sometimes the company who owns the application need some data to improve (feedbacks for instance). Therefore it can ask some aggregation to get data from the clients and use it.

The users receive a notification and can accept it or not. The company must justify why it needs these data.

### Add and remove

--NOT IMPLEMENTED YET--

To add or remove an app you can go on the admin interface, and chose it from a basic store. It will install the docker on the server, and give you the file to install on your smartphone if there is one.

### Domains

To communicate simply with the application, a domain is assigned to each application. The main server is resolved by X.wepn.social, where X has to be chosen at initialization. In order to go public, you have to check that the domain is not already taken.
A new application is assigned Y.X.wepn.social where Y is defined in the application configuration. Every domain is pointing to a unique ip, a reverse proxy (nginx) is in charge of redirecting the requests.

