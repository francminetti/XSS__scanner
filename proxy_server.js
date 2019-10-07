/* MODULES */

var express = require('express');
var path = require('path');
var bodyParser = require('body-parser');
var XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
var http = require('http');
    
/* INITIALIZATION */

var xhr = new XMLHttpRequest();                                   /* object instance xhr for node.js (emulator) */
var app = express();                                              /* instance of the express object (an express app) */

app.use('/static', express.static(__dirname + '/public'));        /* initialization of node.js objects */
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

var data_url = "";                                                /* variable to contain the url of the various requests */
var data_source;                                                  /* variable to contain the source codes of the various HTTP responses */


/*************************
*     EVENT HANDLERS     *
*************************/

app.get('/', function (req, res)                                /* event handler for calls to the homepage */
{
  res.sendFile(path.join(__dirname + '/XSS_scanner.html'));
});

app.get('/guida.html', function(req, res)                      /* event handler for calls to the guide page */
{
  res.sendFile(path.join(__dirname + '/guide.html'));
});

app.get('/xhr.js', function (req, res)                          /* event handler for calls to the xhr.js script of the homepage */
{
  res.sendFile(path.join(__dirname + '/xhr.js'));
});

app.get('/dinamic.js', function (req, res)                      /* event handler for calls to the dinamic.js script of the homepage */
{
  res.sendFile(path.join(__dirname + '/dinamic.js'));
});

app.get('/style.css', function(req, res)                        /* event handler for calls to the stylesheet */
{
  res.sendFile(path.join(__dirname + '/style.css'));
});

app.get('/favicon.ico', function (req, res)                      /* event handler for calls to the favicon.ico */
{
  res.sendFile(path.join(__dirname + '/favicon.ico'));
});

app.post('/', function (req, res)                               /* event handler for POST calls related to submit of the homepage form (when requesting the source of a url to be analyzed)*/
{
  data_url = req.body.url;                                     /* retrieves the url of the document to be analyzed from the body of the POST call */
  xhr.open('GET', data_url, false);                            /* instantiate a GET call for that url (synchronous)*/
  xhr.send();                                                  /* do the call */
  console.log('requested source code from ' + data_url);
  data_source = xhr.responseText;                              /* retirves the source code to analyzed and send it to the browser */
  res.send(data_source);
});

app.post('/injection_get', function (req, res)                   /* event handler for POST calls related to the injection attempt */
{
  data_url = req.body.url;                                       /* retrieves the url containing an attempt to inject from the body of the POST call */
  xhr.open('GET', data_url, false);                              /* retrieves the requested page in synchronous mode */
  xhr.send();
  console.log('requested source code from ' + data_url);
  console.log('HTTP response status code: ' + xhr.status);
  
  if(xhr.status == 403 || xhr.status == 0)                      /* if the answer is of the type access denied 403 sends a 403 with empty body to the browser */
  {
    res.sendStatus(403);
  }
  else
  {
    data_source = xhr.responseText;                             /* send the document to be analyzed to the client */
    res.send(data_source);
  }
});


app.listen(8083);                                               /* listens for the server on port 8083 */
console.log('--------------------------------------------------------------------\nserver listening at port 8083...\n--------------------------------------------------------------------\n');