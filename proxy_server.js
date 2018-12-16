/* MODULI UTILIZZATI */

var express = require('express');
var path = require('path');
var bodyParser = require('body-parser');
var XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
var http = require('http');
    
/* INIZIALIZZAZIONI */

var xhr = new XMLHttpRequest();                                   /* istanza dell'oggetto xhr per node.js (emulatore) */
var app = express();                                              /* istanza dell'oggetto express(un'app express) */

app.use('/static', express.static(__dirname + '/public'));        /* inizializzazioni degli oggetti node.js */
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

var data_url = "";                                                /* variabile per contenere gli url delle varie richieste */
var data_source;                                                  /* variabile per contenere i codici sorgente delle varie richieste */


/*************************
*     EVENT HANDLERS     *
*************************/

app.get('/', function (req, res)                                /* event handler per le chiamate all'homepage */
{
  res.sendFile(path.join(__dirname + '/XSS_scanner.html'));
});

app.get('/guida.html', function(req, res)                      /* event handler per le richieste della pagina di guida */
{
  res.sendFile(path.join(__dirname + '/guida.html'));
});

app.get('/post.js', function (req, res)                          /* event handler per le chiamate GET allo script post.js dell'homepage */
{
  res.sendFile(path.join(__dirname + '/post.js'));
});

app.get('/xhr.js', function (req, res)                          /* event handler per le chiamate GET allo script xhr.js dell'homepage */
{
  res.sendFile(path.join(__dirname + '/xhr.js'));
});

app.get('/dinamic.js', function (req, res)                      /* event handler per le chiamate GET allo script dinamic.js dell'homepage */
{
  res.sendFile(path.join(__dirname + '/dinamic.js'));
});

app.get('/style.css', function(req, res)                        /* event handler per le chiamate GET al foglio di stile */
{
  res.sendFile(path.join(__dirname + '/style.css'));
});

app.get('/favicon.ico', function (req, res)                      /* event handler per le chiamate GET allo script xhr.js dell'homepage */
{
  res.sendFile(path.join(__dirname + '/favicon.ico'));
});

app.post('/', function (req, res)                               /* event handler per le chiamate POST relative al submit() del form dell'homepage (quando si richiede il sorgente di un'url da analizzare)*/
{
  data_url = req.body.url;                                     /* recupera l'url del documento da analizzare dal body della chiamata POST */
  xhr.open('GET', data_url, false);                            /* istanzia una chiamata GET per quell'url (sincrona)*/
  xhr.send();                                                  /* effettua la chiamata */
  console.log('requested source code from ' + data_url);
  data_source = xhr.responseText;                              /* prende il sorgente in risposta e lo invia al client */
  res.send(data_source);
});

app.post('/injection_get', function (req, res)                   /* event handler per le chiamate POST relative al tentativo di iniezione (via xhr)*/
{
  data_url = req.body.url;                                       /* recupera l'url contenente un tentativo d'iniezione dal body della chiamata POST */
  xhr.open('GET', data_url, false);                              /* recupera la pagina richiesta in modalità sincrona */
  xhr.send();
  console.log('requested source code from ' + data_url);
  console.log('HTTP response status code: ' + xhr.status);
  
  if(xhr.status == 403 || xhr.status == 0)                      /* se la risposta è di tipo access denied 403 invia una 403 con body vuoto al client */
  {
    res.sendStatus(403);
  }
  else
  {
    data_source = xhr.responseText;                             /* invia il documento da analizzare al client */
    res.send(data_source);
  }
});

app.post('/injection_post', function (req, res)                  /* event handler per le chiamate POST relative al tentativo di iniezione (via xhr) */
{
  var _host = req.body.host;                                     /* setta tutti i parametri che andranno a finire nell'header HTTP recuperandoli dall'url della chiamata POST al proxy */
  var malevolous_body = req.body.malevolous_body;
  var referer = req.body.referer;
  var path = req.body.path;

  if(/^[^\/]/.test(path))
  {
    path = '/' + path;
  }

 
 function postCode()             // funzione per effettuare una chiamata post malevola
 { 
  
  console.log('malevolous body = ' + malevolous_body);

  var post_options = {                                  /* oggetto contenente l'header HTTP che verrà inviato */
      host: _host,
      path: path,
      method: 'POST',
      headers: {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'it,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Referer': referer,
            'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(malevolous_body),
            'Connection': 'close',
            'Upgrade-Insecure-Requests': 1
      }
  };
  // console.log(post_options);
 
  var post_req = http.request(post_options, function(resp){                /* setta la richiesta HTTP e recupera la risposta in modo asincrono */
      resp.setEncoding('utf8');
      
      resp.on('data', function (chunk) {
      data_source += chunk;
  });
      
      resp.on('end', function(){                                          /* terminata la ricezione della risposta la invia al client */
        res.send(data_source);
     });
  });
  
  post_req.write(malevolous_body);                                       /* invia la richiesta malevola */
  post_req.end();
  }
postCode();
});

app.listen(8083);                                               /* mette in ascolto il server sulla porta 8083 */
console.log('--------------------------------------------------------------------\nserver listening at port 8083...\n--------------------------------------------------------------------\n');