var express = require('express');

var app = express();

var bodyParser = require('body-parser')
var telnet = require('telnet-client')
app.use( bodyParser.json() );       // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({     // to support URL-encoded bodies
  extended: true
}));

/*var mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/global_login');
const User = mongoose.model('User', { username: String, ip: Array}, "users");*/

var sqlite = require('sqlite3');
let db = new sqlite.Database('db/global.db', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the global database.');
});

var connection = new telnet();
var params = {
  host: '10.8.0.1',
  port: 7500
  // removeEcho: 4
};
connection.connect(params);

app.use(express.static(__dirname));

app.get('/newuser', function(req,res) {
  console.log("received")
  var ip = req.query.id;
  var sys = require('sys')
  var exec = require('child_process').exec;

  // executes `pwd`
  var command = "";
  var x = 1;
  command += "cd /etc/openvpn/easy-rsa; /etc/openvpn/easy-rsa/easyrsa build-client-full myvpn-"+ip+" nopass; ";
  command += "sed '2idev tun-"+ip+"' /etc/openvpn/client-common.txt > ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo '<ca>' >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo '</ca>' >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo \"<cert>\" >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "cat /etc/openvpn/easy-rsa/pki/issued/myvpn-"+ip+".crt >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo \"</cert>\" >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo \"<key>\" >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "cat /etc/openvpn/easy-rsa/pki/private/myvpn-"+ip+".key >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo \"</key>\" >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "echo \"<tls-auth>\" >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
  command += "cat /etc/openvpn/ta.key >> ~/openvpn-clients/myvpn-"+ip+".ovpn; "
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

app.get('/login', function(req, res) {
    var ip = req.headers["x-forwarded-for"];
    if(ip == undefined) { ip = req.connection.remoteAddress}
    getUsername(ip).then(function(username) {
      res.render('login.ejs', {address: ip, username:username});
    })
});

app.post('/blockfb', function(req, res) {
  var ip = req.headers["x-forwarded-for"];
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
      res.redirect("/dashboard")
      return;
    }

    var start = req.body.start;
    var end = req.body.end;
    db.get("SELECT * FROM block WHERE username=?", [username], (err, row) => {
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
        db.run("DELETE from block WHERE username=?", [username], (err)=>{
          if(err) throw err;
        });
        db.run("INSERT INTO block VALUES(NULL, ?, ?, ?)", [username, start, end], (err)=>{if(err) throw err;});
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
      getUsername(ip).then(function(username) {
        if(username == undefined) {
          res.redirect("/login");
          return;
        }

        db.get("SELECT * FROM blockfb WHERE username=?", [username], (err, row) => {
          if(err) throw err;
          if(row != undefined) {
            res.render('block.ejs', {name: username, address: ip, start: row.start, end: row.end});
          }
          else {
            res.render('block.ejs', {name: username, address: ip, start: 10, end: 10});
          }
        });

      });
});

app.get(["/", "/dashboard"], function(req,res) {
  var ip = req.headers["x-forwarded-for"];
  if(ip == undefined) { ip = req.connection.remoteAddress}

    var fs = require('fs')
    fs.readFile("/etc/openvpn/openvpn-status.log", 'utf8', function(err,data) {
      if(err) {
        throw err;
      }
      console.log(data)
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
        console.log(line)
        if(next) {
          console.log("enters")
          var tab = line.split(",")
          users_promise.push(getUsername(tab[0]));
          var temp = tab[1].split("-");
          json_user.push({"ip":tab[0],"username":temp[temp.length-1],"lastref":tab[tab.length-1], "ads":[{"domain":"ad.machin.bidule", "bandwidth":153.4}]});
          c+=1;
        }
      }

      Promise.all(users_promise).then(function(users) {
        for(var i = 0; i < users.length; i++) {
          if(users[i]!=undefined) {
            json_user[i].username = users[i];
          }

        }
        var logs = [];
        db.all("SELECT * FROM traffic ORDER BY id DESC LIMIT 150", (err, rows) => {
          if(err) throw err;
          if(rows != undefined) {
            rows.forEach(function (row) {
                json_user.forEach(function(user) {
                  console.log(user)
                  if(user["ip"]==row["source"]) {
                    row["username"] = user["username"];
                  }
                })
                logs.push(row);
            })
          }
          console.log(json_user)
          res.render('dashboard.ejs', {name: "", address: ip, users: json_user, logs:logs});
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


app.listen(5000, "10.8.0.1");
