CREATE TABLE users(
id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
username TEXT NOT NULL);
CREATE TABLE ips(
id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
username TEXT NOT NULL,
ip TEXT NOT NULL);
CREATE TABLE "blockfb"(
id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
username text not null,
start text not null,
end text not null);
CREATE TABLE "raw_traffic"(id integer PRIMARY KEY AUTOINCREMENT,
source TEXT,
dest TEXT,
date TEXT,
prot TEXT,
info TEXT, domain TEXT);
CREATE TABLE blockadult(id integer PRIMARY KEY AUTOINCREMENT NOT NULL, username TEXT);
CREATE TABLE bluetooth_devices(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, mac TEXT, name TEXT, vendor TEXT, last_seen TEXT, paired TEXT);
CREATE TABLE day_traffic(ip TEXT, date TEXT, protocol TEXT, amount INTEGER);
CREATE TABLE ip_traffic(source TEXT, dest TEXT, amount INTEGER, domain TEXT);
CREATE TABLE blockgen(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT);
CREATE TABLE ip_location(ip TEXT, location TEXT);
