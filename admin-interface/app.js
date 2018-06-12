var express = require('express');

var app = express();
var exec = require('child_process').exec;

var bodyParser = require('body-parser')
var request = require('request');
var telnet = require('telnet-client')
app.use( bodyParser.json() );       // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({     // to support URL-encoded bodies
  extended: true
}));

/*var mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/global_login');
const User = mongoose.model('User', { username: String, ip: Array}, "users");*/

var sqlite = require('sqlite3');
let db = new sqlite.Database('/host/globaldb/global.db', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the global database.');
});
db.run( 'PRAGMA journal_mode = WAL;' );

// var connection = new telnet();
// var params = {
//   host: '10.8.0.1',
//   port: 7500
//   // removeEcho: 4
// };
//connection.connect(params);

app.use(express.static(__dirname));

app.get('/deleteuser', (req,res)=>{
  var realip = req.query.ip;
  console.log(realip)
  request.post(
      'http://10.8.0.2:5000/deleteuser',
      {form:{ip:realip}},
      function (error, response, body) {
          if (!error && response.statusCode == 200) {
              console.log(body)
          }
      }
  );
});

app.get('/newuser', function(req,res) {
  console.log("received")
  var ip = req.query.id;
  var sys = require('sys')


  // executes `pwd`
  var command = "";
  var x = 1;
  command += "cd /host/openvpn/easy-rsa; /host/openvpn/easy-rsa/easyrsa build-client-full myvpn-"+ip+" nopass; ";
  command += "cat /host/openvpn/client-common.txt > ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo '<ca>' >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "cat /host/openvpn/easy-rsa/pki/ca.crt >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo '</ca>' >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo \"<cert>\" >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "cat /host/openvpn/easy-rsa/pki/issued/myvpn-"+ip+".crt >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo \"</cert>\" >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo \"<key>\" >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "cat /host/openvpn/easy-rsa/pki/private/myvpn-"+ip+".key >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo \"</key>\" >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo \"<tls-auth>\" >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "cat /host/openvpn/ta.key >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo \"</tls-auth>\" >> ~/openvpn-clients/myvpn-"+ip+".ovpn"

  exec(command, function (error, stdout, stderr) {
    if (error !== null) {
      console.log('exec error: ' + error);
    }
    console.log(stdout);
    console.log(stderr);
    var fs = require('fs')
    if(req.query.type == "string") {
      fs.readFile('/home/ubuntu/openvpn-clients/myvpn-'+ip+'.ovpn', function(err, data) {
        if(err) {throw err;}
        res.send(200,data);
      });
    }else {
      res.writeHead(200, {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": "attachment; filename=myvpn-"+ip+".ovpn"
          });
      fs.createReadStream('/home/ubuntu/openvpn-clients/myvpn-'+ip+'.ovpn').pipe(res);
    }

    //res.sendFile('/home/ubuntu/openvpn-clients/myvpn-'+ip+'.ovpn')

  });


});

app.get("/status", function(req, res) {
  var ip_status = req.query.ip;


  var raw_analyze_p= new Promise((resolve,reject)=>{
    db.all("SELECT * FROM raw_traffic WHERE source=? ORDER BY id DESC LIMIT 150", [ip_status], (err, rows) => {
      if(err) throw err;
      var logs = [];
      if(rows != undefined) {
        rows.forEach(function (row) {
            logs.push(row);
        })
      }
      resolve(logs);
    });
  });

  var ip_analyze_p= new Promise((resolve,reject)=>{
    db.all("SELECT * FROM ip_traffic WHERE source=?", [ip_status], (err, rows) => {
      if(err) throw err;
      var logs_ip = {"labels":[], "values":[]};
      var dict = {};
      if(rows != undefined) {
        rows.forEach(function (row) {
          var ident = row["dest"]+" - "+row["domain"];
            if(ident in dict) {
              dict[ident] += row["amount"]
            }
            else {
              dict[ident] = row["amount"]
            }
        })
        var maximum = 0;
        for(var key in dict) {
          if(maximum == 0) {
            maximum = dict[key]
          }
          if(dict[key] >= maximum) {
            maximum = dict[key]
          }
        }

        for(var key in dict) {
          if(dict[key] / maximum >= 1./100) {
            logs_ip.labels.push(key)
            logs_ip.values.push(dict[key])
          }
        }
        resolve(logs_ip);
      }

    });
  });


  Date.prototype.addDays = function(days) {
      var date = new Date(this.valueOf());
      date.setDate(date.getDate() + days);
      return date;
  }

  function getDates(startDate, stopDate) {
      var dateArray = new Array();
      var currentDate = startDate;
      while (currentDate <= stopDate) {
          dateArray.push(new Date (currentDate));
          currentDate = currentDate.addDays(1);
      }
      return dateArray;
  }

  var day_analyze_p = new Promise((resolve,reject)=>{
    db.all("SELECT * FROM day_traffic WHERE ip=?", [ip_status], (err, rows) => {
      if(err) throw err;
      if(rows != undefined) {
        var dict = {};
        rows.forEach(function (row) {
            var str_date = new Date(row["date"]).toLocaleDateString();
            if(str_date in dict) {
              dict[str_date] += row["amount"]
            }
            else {
              dict[str_date] = row["amount"]
            }
        })
        var newl = {"labels":[], "values":[]}
        var max = [new Date(Object.keys(dict)[Object.keys(dict).length-1]), new Date()].reduce(function (a, b) { return a > b ? a : b; });
        for(var date of getDates(new Date(Object.keys(dict)[0]), max)) {
          newl["labels"].push(date.toLocaleDateString())
          if(!(date.toLocaleDateString() in dict)) {
            newl["values"].push(0)
          }
          else {
            newl["values"].push(dict[date.toLocaleDateString()]);
          }
        }
        var average_packets = 0;

        for(var x of newl.values) {
          average_packets += x/newl.values.length;
        }
        average_packets = Math.round(average_packets)
        var logs_day = newl;
        resolve({logs_day:logs_day, average_packets:average_packets})
      }
    });
  });

  var protocol_analyze_p = new Promise((resolve,reject)=>{
    db.all("SELECT * FROM day_traffic WHERE ip=?", [ip_status], (err, rows) => {
      if(err) throw err;
      if(rows != undefined) {
        var dict = {};
        rows.forEach(function (row) {
            if(row["protocol"] in dict) {
              dict[row["protocol"]] += row["amount"]
            }
            else {
              dict[row["protocol"]] = row["amount"]
            }
        })

        var maximum = 0;
        for(var key in dict) {
          if(maximum == 0) {
            maximum = dict[key]
          }
          if(dict[key] >= maximum) {
            maximum = dict[key]
          }
        }

        var newl = {"labels":[], "values":[]}
        for(var key in dict) {
          if(dict[key] / maximum >= 1./100) {
            newl.labels.push(key)
            newl.values.push(dict[key])
          }
        }
        resolve(newl)
      }
    });
  });

  var username_p = getUsername(ip_status);

  var ips = {}
  db.all("SELECT * FROM ip_location", (err, rows)=>{
    if(err) throw err;
    if(rows != undefined) {
      rows.forEach(function (row) {
          ips[row["ip"]] = row["location"]
      });
    }
  })

  Promise.all([username_p, raw_analyze_p ,protocol_analyze_p, day_analyze_p, ip_analyze_p]).then((params)=>{
    res.render('status.ejs', {username:params[0], address: ip_status, average_packets:params[3].average_packets,
      logs_protocol:params[2],
      logs_ip:params[4],
       logs_day:params[3].logs_day, logs:params[1], ips:ips});
  })
});

app.get('/login', function(req, res) {
    var ip = req.headers["x-forwarded-for"];
    if(ip == undefined) { ip = req.connection.remoteAddress}
    getUsername(ip).then(function(username) {
      res.render('login.ejs', {address: ip, username:username});
    })
});

app.post('/bluetooth/activity', function(req, res) {
  var ip = req.headers["x-forwarded-for"];
  if(ip == undefined) { ip = req.connection.remoteAddress}

  for(var device of req.body.devices) {
    db.run("DELETE FROM bluetooth_devices WHERE mac=?", [device["mac_address"]], (err)=>{if(err) throw err;});
    db.run("INSERT INTO bluetooth_devices(mac, name, vendor, last_seen, paired) VALUES(?, ?, ?, ?, ?)", [device["mac_address"], device["name"], device["vendor"], new Date().toUTCString(), device["paired"]], (err)=>{if(err) throw err;});
  }
  res.send("ok")
});

app.post('/blockfb', function(req, res) {
  var ip = req.body.ip;
  if(ip == undefined) { ip = req.connection.remoteAddress}
  getUsername(ip).then(function(username) {
    if(username == undefined) {
      res.redirect("/login");
      return;
    }


    if(req.body.unblock != undefined) {
      db.run("DELETE from blockfb WHERE username=?", [username], (err)=>{
        if(err) throw err;
      });
      exec("sudo bash /home/ubuntu/unblockip_fb.sh "+ip, function (error, stdout, stderr) {});
      res.redirect("/dashboard")
      return;
    }

    var start = req.body.start;
    var end = req.body.end;
    console.log(req.body)
    db.get("SELECT * FROM blockfb WHERE username=?", [username], (err, row) => {
      if(err) throw err;
      var ok = true;
      if(Date.parse('01/01/2011 '+start+':00') >= Date.parse('01/01/2011'+end+':00')) {
        ok = false;
      }
      if(row != undefined) {
        ok = false;
        var d = new Date();
        var dateString = "" + d.getFullYear() + "/" + (d.getMonth() + 1) + "/" + d.getDate();
        if(Date.parse(dateString+' '+row.start+':00') > d || Date.parse(dateString+' '+row.end+':00') < d) {
            ok = true;
        }
      }
      if(ok) {
        db.run("DELETE from blockfb WHERE username=?", [username], (err)=>{
          if(err) throw err;
        });
        db.run("INSERT INTO blockfb VALUES(NULL, ?, ?, ?)", [username, start, end], (err)=>{if(err) throw err;
          exec("sudo bash /home/ubuntu/blockip_fb.sh "+ip, function (error, stdout, stderr) {});
        });
      }

    });
    res.redirect("/dashboard")
  });
});

app.post('/blockadult', function(req, res) {
  var ip = req.headers["x-forwarded-for"];
  if(ip == undefined) { ip = req.connection.remoteAddress}
  getUsername(ip).then(function(username) {
    if(username == undefined) {
      res.redirect("/login");
      return;
    }

    if(req.body.unblock != undefined) {
      db.run("DELETE from blockadult WHERE username=?", [username], (err)=>{
        if(err) throw err;
      });
      res.redirect("/dashboard")
      return;
    }

    db.run("DELETE from blockadult WHERE username=?", [username], (err)=>{
      if(err) throw err;
    });
    db.run("INSERT INTO blockadult VALUES(NULL, ?)", [username], (err)=>{if(err) throw err;});
    res.redirect("/dashboard")
  });
});

app.get(['/block'], function(req, res) {
      var ip = req.headers["x-forwarded-for"];
      if(ip == undefined) { ip = req.connection.remoteAddress}
      if(req.query && req.query.ip) {
        ip = req.query.ip;
      }
      getUsername(ip).then(function(username) {
        if(username == undefined) {
          res.redirect("/login");
          return;
        }

        db.get("SELECT * FROM blockfb WHERE username=?", [username], (err, row) => {
          if(err) throw err;
          if(row != undefined) {
            console.log(row)
            res.render('block.ejs', {name: username, address: ip, start: row.start, end: row.end});
          }
          else {
            res.render('block.ejs', {name: username, address: ip, start: 10, end: 10});
          }
        });

      });
});

app.post('/blockgen', function(req,res) {
  var ip = req.body.ip;
  if(ip == undefined) { ip = req.connection.remoteAddress}
  getUsername(ip).then(function(username) {
    if(username == undefined) {
      res.redirect("/login");
      return;
    }

    if(req.body.unblock != undefined) {
      db.run("DELETE from blockgen WHERE username=?", [username], (err)=>{
        if(err) throw err;
      });
      exec("sudo bash /home/ubuntu/unblockip.sh "+ip, function (error, stdout, stderr) {});
      res.redirect("/dashboard")
      return;
    }

    db.run("DELETE from blockgen WHERE username=?", [username], (err)=>{
      if(err) throw err;
    });
    db.run("INSERT INTO blockgen VALUES(NULL, ?)", [username], (err)=>{if(err) throw err;});
    exec("sudo bash /home/ubuntu/blockip.sh "+ip, function (error, stdout, stderr) {});
    res.redirect("/dashboard")
  });
});

app.get(["/", "/dashboard"], function(req,res) {
  var ip = req.headers["x-forwarded-for"];
  if(ip == undefined) { ip = req.connection.remoteAddress}

    var fs = require('fs')
    fs.readFile("/host/openvpn/openvpn-status.log", 'utf8', function(err,data) {
      if(err) {
        throw err;
      }
      var lines = data.split("\n");
      var json_user = [];
      var next = false;
      var c = 0;
      users_promise = []
      for(var line of lines) {
        if(line.startsWith("Virtual Address")) {
          next = true;
          continue;
        }
        if(line.startsWith("GLOBAL STATS")) {
          next=false;
          break;
        }
        if(next) {
          var tab = line.split(",")
          users_promise.push(getUsername(tab[0]));
          var temp = tab[1].split("-");
          json_user.push({"ip":tab[0],"username":temp[temp.length-1],"lastref":tab[tab.length-1], "ads":[{"domain":"ad.machin.bidule", "bandwidth":153.4}]});
          c+=1;
        }
      }

      var bluetooth_devices = [];
      db.all("SELECT * FROM bluetooth_devices", (err, rows)=>{
        if(err) throw err;
        if(rows != undefined) {
          rows.forEach(function (row) {
            bluetooth_devices.push(row)
          });
        }
      })

      var ips = {}
      db.all("SELECT * FROM ip_location", (err, rows)=>{
        if(err) throw err;
        if(rows != undefined) {
          rows.forEach(function (row) {
              ips[row["ip"]] = row["location"]
          });
        }
      })

      Promise.all(users_promise).then(function(users) {
        for(var i = 0; i < users.length; i++) {
          if(users[i]!=undefined) {
            json_user[i].username = users[i];
          }

        }
        var logs = [];
        db.all("SELECT * FROM raw_traffic ORDER BY id DESC LIMIT 50", (err, rows) => {
          if(err) throw err;
          if(rows != undefined) {
            rows.forEach(function (row) {
                json_user.forEach(function(user) {
                  if(user["ip"]==row["source"]) {
                    row["username"] = user["username"];
                  }
                })
                logs.push(row);
            })
          }
          res.render('dashboard.ejs', {name: "", address: ip, users: json_user, bluetooth_devices:bluetooth_devices, logs:logs, ips:ips});
        });
      });
    });

});

app.post('/login', function(req,res) {

  if(req.body.username == undefined) {
    res.redirect("/login");
    return;
  }

  var ip = "";
  if(req.body.virtualip == undefined) {
    ip = req.headers["x-forwarded-for"];
    if(ip == undefined) { ip = req.connection.remoteAddress}
  } else {
    ip = req.body.virtualip;
  }
  db.run("DELETE FROM ips WHERE ip = ?", [ip], (err) => {if(err) throw err;});
  db.run("INSERT INTO ips (username, ip) VALUES(?, ?)", [req.body.username, ip], (err) => {if(err) throw err;})
  res.redirect('https://www.google.com');
  /*User.find(function(err, users) {
    for(var us of users) {
      us.ip = us.ip.filter(item => item != req.connection.remoteAddress)
      if(us.ip.length == 0) {
        us.remove()
      }
      else {
        us.save()
      }

    }

  });

  User.findOne({ "username":req.body.username}, function (err, user) {
    if (err) {
      throw err;
    }
    else {
      if(user == null) {
        var x = new User({"username":req.body.username, "ip":[req.connection.remoteAddress]});
        x.save();
      }
      else {
          user.ip.push(req.connection.remoteAddress);
          user.save();
      }
      res.redirect('https://www.google.com');
    }

  });*/
});



function getUsername(ip) {
  return new Promise(function(resolve, reject) {
    db.get("SELECT * FROM ips WHERE ip=?", [ip], (err, row) => {
      if(err) throw err;
      if(row==undefined) {
        resolve(row)
      }
      else {
        resolve(row.username);
      }
    });
  });
}


app.listen(5000, "0.0.0.0");
