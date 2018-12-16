/**************************************************************************
*  funzione per creare la lista di parametri che finirà nel body delle    *
*  chiamate POST.                                                         *
**************************************************************************/

function make_param(input)
{
   doc.post_header.referer = doc._url;
   doc.post_header.host = doc._url.replace(/^((ftp:\/\/|http:\/\/|https:\/\/|www\.){1})/, '');
   doc.post_header.host = doc.post_header.host.replace(/(\/[^\/]+[\/]?)+$/g, '');
   doc.post_header.host = doc.post_header.host.replace('/', '');
   doc.post_header.path = form_obj.form_action[l].replace(/&/g, '%26');
   
   for(i = 0; i < input.length; i++)                                                                                 /* per tutti gli input del form che si sta analizzando */
   {
      if(is_sent(input[i]))                                                                                          /* se l'input in questione andrà a finire nel body del messaggio HTTP */
      {
         if(is_injectable(input[i]))                                                                                 /* se l'input è iniettabile */
         {
             doc.post_header.malevolous_body += (input[i].getAttribute('name') + "=" + doc.injection_2 + '&');       /* attribuiscigli un valore con semantica di script */
             console.log(doc.post_header.malevolous_body + ' 1');
             report.vuln_input = input[i].getAttribute('name');
         }
         else
         {
            doc.post_header.malevolous_body += (input[i].getAttribute('name') + '=' + (input[i].getAttribute('value') || '') + '&');      /* attribuiscigli il valore che possiede */
            console.log(doc.post_header.malevolous_body);
         }
      }
   }
   
   doc.post_header.malevolous_body = doc.post_header.malevolous_body.substr(0, (doc.post_header.malevolous_body.length - 1));      /* rimuovi dall'url malevolo l'ultima "&" */            
   doc.post_header.malevolous_body = doc.post_header.malevolous_body.replace(/&/g, '%26');                                         /* rimpiazza tutte le "&" con la loro codifica url per evitare che nel corpo della post verso il proxy ci siano problemi */
   doc.post_header.malevolous_body = doc.post_header.malevolous_body.replace(/ /g, '+');                                           /* rimpiazza tutti gli spazi con un "+"(urlencoded) */
}


/******************************************************************************************
*  funzione per richiedere la pagina a seguito di una possibile iniezione con metodo post *
******************************************************************************************/

function send_injection_post()
{
    make_param(form_obj.input[l]);
    xhr.open('POST', 'http://localhost:8083/injection_post', false);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.send("malevolous_body=" + doc.post_header.malevolous_body + '&host=' + doc.post_header.host + '&referer=' + doc.post_header.referer + '&path=' + doc.post_header.path);
    console.log('injection_url_request_sent(POST)');
    console.log(doc.post_header.malevolous_body);
    
    if(xhr.status === 403)                                                       /* se il codice HTTP di risposta è 403(access denied) */
    {
      console.log("richiesta bloccata da un web application firewall...");       /* aggiorna il report di analisi */
      report.waf = true;
    }
    else
    {
      doc.data_source = parser.parseFromString(xhr.responseText, "text/html");   /* recupera la risposta(parsandola ad oggetto DOM) */
      console.log("injection_data_retrived");
      doc.vaerifyInjection();                                                    /* verifica se ci sono iniezioni che hanno avuto successo */
    }          
}