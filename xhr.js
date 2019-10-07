/* XHR */ /* clientside code that analyze the presence of get form and analyze the injection attempt to find out if there is a successfull one */


var xhr;                   /* xhr object instance */

try
{
   xhr = new XMLHttpRequest();            /* try to intances the xhr object for a browser that isn't IE */
}
catch(error)
{
   try
   {
      xhr = new ActiveXObject("Microsoft.XMLHTTP");         /* try to intances the xhr object for IE */
   }
   catch(error)
   {
      console.log("error: XHR object unaviable...");
   }
}
 
var parser = new DOMParser();               /* DOMparser object instance */

var i, j;                    /* index for cicles inside the functions */
var k;                       /* index for the cicle that iterate trough the list of urls */
var l;                       /* index of the cycle concerning the forms of the document under analysis */
var n;                       /* index of the innermost cycle during advanced scanning */

/***************************************************************************************************
*  object to keep in memory the source code of the document, the injections and other variables	   *
***************************************************************************************************/

var doc =
{
    data_source : "",                                                                                                 /* pages source code */
    injection_2 : '%22%3E%3Cscript%20name%3D%22inject%22%3Ealert(%22xss%22)%3B%3C%2Fscript%3E%3Cxss',                 /* injection with simple scan mode */
    
                          // hexadecimal injection equivalent to: &#x22;&#x3e;&#x3c;script&#x3e;alert(&#x27;xss&#x27;);&#x3c;&#x2f;script&#x3e;
    injection_hex : ['%26%23x22%3B%26%23x3e%3B%26%23x3c%3Bscript%26%23x3e%3Balert(%26%23x27%3Bxss%26%23x27%3B)%3B%26%23x3c%3B%26%23x2f%3Bscript%26%23x3e%3B', '%26%23x022%3B%26%23x03e%3B%26%23x03c%3Bscript%26%23x03e%3Balert(%26%23x027%3Bxss%26%23x027%3B)%3B%26%23x03c%3B%26%23x02f%3Bscript%26%23x03e%3B', '%26%23x0022%3B%26%23x003e%3B%26%23x003c%3Bscript%26%23x003e%3Balert(%26%23x0027%3Bxss%26%23x0027%3B)%3B%26%23x003c%3B%26%23x002f%3Bscript%26%23x003e%3B', '%26%23x00022%3B%26%23x0003e%3B%26%23x0003c%3Bscript%26%23x0003e%3Balert(%26%23x00027%3Bxss%26%23x00027%3B)%3B%26%23x0003c%3B%26%23x0002f%3Bscript%26%23x0003e%3B', '%26%23x000022%3B%26%23x00003e%3B%26%23x00003c%3Bscript%26%23x00003e%3Balert(%26%23x000027%3Bxss%26%23x000027%3B)%3B%26%23x00003c%3B%26%23x00002f%3Bscript%26%23x00003e%3B', '%26%23x0000022%3B%26%23x000003e%3B%26%23x000003c%3Bscript%26%23x000003e%3Balert(%26%23x0000027%3Bxss%26%23x0000027%3B)%3B%26%23x000003c%3B%26%23x000002f%3Bscript%26%23x000003e%3B'],
                          // decimal injection equivalent to: &#34;&#62;&#60;script&#62;alert&#40;&#39;xss&#39;&#41;&#59;&#60;&#47;script&#62;
    injection_dec : ['%26%2334%3B%26%2362%3B%26%2360%3Bscript%26%2362%3Balert%26%2340%3B%26%2339%3Bxss%26%2339%3B%26%2341%3B%26%2359%3B%26%2360%3B%26%2347%3Bscript%26%2362%3B', '%26%23034%3B%26%23062%3B%26%23060%3Bscript%26%23062%3Balert%26%23040%3B%26%23039%3Bxss%26%23039%3B%26%23041%3B%26%23059%3B%26%23060%3B%26%23047%3Bscript%26%23062%3B', '%26%230034%3B%26%230062%3B%26%230060%3Bscript%26%230062%3Balert%26%230040%3B%26%230039%3Bxss%26%230039%3B%26%230041%3B%26%230059%3B%26%230060%3B%26%230047%3Bscript%26%230062%3B', '%26%2300034%3B%26%2300062%3B%26%2300060%3Bscript%26%2300062%3Balert%26%2300040%3B%26%2300039%3Bxss%26%2300039%3B%26%2300041%3B%26%2300059%3B%26%2300060%3B%26%2300047%3Bscript%26%2300062%3B'],
    
    _url : "",                                                                                                        /* url to be analyzed */
    _url_copy : '',                                                                                                   /* copy of url useful to restore it */
    malevolous_url : "",                                                                                              /* malicious url within a possible injection */
    
    
    vaerifyInjection : function()            // function to verify if an injection has been successfull
    {
        var inject = this.data_source.getElementsByName('inject');         
        if(inject.length > 0)                                              
        {
            report.reflected_get = true;                                   /* update the report */
            make_report(k, report.vuln_input);                             /* update the page with the correct CSS property */
        }
        console.log("l'iniezione è stata riflessa " + inject.length + " volte");
    }
};

/*********************************************************************************************
*  object for keep track of the form, input etc.. in the document analyzed					 *
*********************************************************************************************/

var form_obj =
{
    valid : false,
    form : [],                             /* array to contain the forms of the document */
    form_method : [],                      /* array to store form methods */
    form_action : [],                      /* array to store form actions */
    valid_form : [],                       /* array of Boolean values to keep information on which forms are attackable */
    input : [],                            /* array of arrays of input fields within forms */
    
    getInput : function(data_source)               // function to retrieve all possible information about the forms from the source
    {
        this.form = data_source.getElementsByTagName('FORM');                   /* takes and stores all the forms of the document being analyzed */
        console.log("numero di form nella pagina: " + this.form.length);
        
        for(i = 0; i < this.form.length; i++)                                   /* for every form of the document being analyzed */
        {
            this.form_action[i] = this.form[i].getAttribute('action');          /* store the actions */
            this.form_method[i] = this.form[i].getAttribute('method');          /* store the methods */
            
            if(this.form_method[i] == null )                                     /* if the form doesn't present any method attribute */
            {
               this.form_method[i] = 'GET';                                     /* thereby is the default GET method */
            }
            this.input[i] = this.form[i].getElementsByTagName('INPUT');         /* store all the inputs */
        }
    },
    
    getInputText : function()                      // function to attribute which forms are valid for an attempted attack and the storage of the relative names of the inputs
    {
        for(i = 0; i < this.form.length; i++)                      /* for each input of each form see if it is 'text', 'search' or without type (therefore 'text', that is default) */
        {                                                          /* if it is increase by one the counter input_text */
            for(j = 0; j < this.input[i].length; j++)              /* and store the NAME for a later injection */
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
    
    clear_form : function()         // function for restoring the values of the form object for its future reuse
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




/********************************************************************************
*  main function to manage the sending of data (url) and their processing		*
********************************************************************************/

function send_address()
{
   make_list();                                                                           /* creates an array of URLs to check */
   
   if(document.getElementById('type').value == 'simple')       // SIMPLE SCAN
   {
      for(k = 0; k < list_array.length; k++)                                              /* for all the URLs to be analyzed */
      {
         doc._url = list_array[k];                                                        /* retrive the URL */
         doc._url_copy = doc._url = doc._url.substr(0, doc._url.length - 1);              /* remove the '\n' character and copy the value in these two variables */
         get_homepage();                                                                  /* retrive the HTML document for that URL */
        
        doc.data_source = parser.parseFromString(xhr.responseText, "text/html");          /* parses the document(as text) and return the relative DOM object */
        form_obj.getInput(doc.data_source);                                               /* retrive all the form and input data from the DOM object */
        form_obj.getInputText();                                                          /* verify wich form si valid for an attack */
        
        if(form_obj.valid)                                                                /* if there is at least 1 attackable form */
        {
            for(l = 0; l < form_obj.form.length; l++)                                     /* for all the forms */
            {
               if(form_obj.valid_form[l] && form_obj.form_method[l] != 'post')            /* if it's possible to inject some code */
               {
                  form_obj.form_action[l] = verify_action_dir(form_obj.form_action[l]);   /* retrive the action of the form */
                  send_injection_get();                                                   /* try an injection */
                  doc._url = doc._url_copy;                                               /* restores the initial value of the url to be able to reuse it */
               }
            }
        }
        else
        {
            console.log('there aren\'t attackable form...');
            report.no_form = true;                                      /* update the report */
        }
       
       report.clear_report();                                           /* restores the value of the report object and the form object to be able to reuse it */
       form_obj.clear_form();
      }
   }
   else        // ADVANCED SCAN
   {
       
      for(k = 0; k < list_array.length; k++)                                              
      {
         
         doc._url = list_array[k];                                                        
        
         doc._url_copy = doc._url = doc._url.substr(0, doc._url.length - 1);              
         get_homepage();                                                                 
        
        doc.data_source = parser.parseFromString(xhr.responseText, "text/html");          
        form_obj.getInput(doc.data_source);                                               
        form_obj.getInputText();                                                          
        
         
         if(form_obj.valid)                                                               
         {
            for(l = 0; l < form_obj.form.length; l++)                                    
            {
               make_adv_url(form_obj.input[l]);                                           /* try to inject Javascript in all the parameters of the querystring(even those hidden) */
            }
            
            for(l = 0; l < form_obj.form.length; l++)                                     /* per tutti i form del documento */
            {
               encoded_injection(form_obj.input[l]);                                      /* prova ad iniettare del codice con codifica decimale(&#YYYYY;) ed esadecimale(&#xYYYYY;) */
            }
            
           
         }
         else
         {
             console.log('non ci sono costrutti attaccabili...');
             report.no_form = true;                                                        
         }
      
       report.clear_report();                                                             
       form_obj.clear_form();
      }
   }
}

/***************************************************************************************
*  function that implement the advanced scan                                           *
***************************************************************************************/

function encoded_injection(input)
{
   var i;                                                                        /* index of cicle */
   
   if(form_obj.valid_form[l] && form_obj.form_method[l] != 'post')               /* if it's possible to inject some code */
   {
      form_obj.form_action[l] = verify_action_dir(form_obj.form_action[l]);      /* retrive the action of the form */
      doc.malevolous_url = doc._url + form_obj.form_action[l] + "?";             /* bulid the fisrt part of the malicious URS */
      
      for(i = 0; i < doc.injection_hex.length; i++)                              /* request the page within the attempt of injection for all the payloads */
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
*  another function that implement the advanced scan            				       *
***************************************************************************************/

function make_adv_url(input)
{
      if(form_obj.valid_form[l] && form_obj.form_method[l] != 'post')            	/* if it's possible to inject some code */
      {
         form_obj.form_action[l] = verify_action_dir(form_obj.form_action[l]);      /* retrive the action of the form */
         doc.malevolous_url = doc._url + form_obj.form_action[l] + "?";             /* build the first part of the malicious URL */
         
         var sent_var = 0;                                                          /* variable to count the number of parameters in the querystring */
         
         for(i = 0; i < input.length; i++)                                          /* for all the input of the form to be analyzed */
         {
            if(is_sent(input[i]))                                                   /* if the input end it up in the querystring */
            {
               sent_var++;                                                          /* increase the number of the parameters */
            }
         }
         
         for(n = 0; n < sent_var; n++)                                                 /* for every input that end up in the querystring */
         {
            doc.malevolous_url = doc._url + form_obj.form_action[l] + "?";             /* build the first part of the malicious URL */
            
            for(i = 0; i < input.length; i++)                                                                                 /* for every input of the form to be analyzed */
            {
               if(is_sent(input[i]))                                                                                          /* if the input end up in the querystring */
               {
                  if(i == n)                                                                                                  /* AND if it's his turn */
                  {
                      doc.malevolous_url += (input[i].getAttribute('name') + "=" + doc.injection_2 + '&');                    /* give him a value within a semantic of script */
                      report.vuln_input = input[i].getAttribute('name');
                  }
                  else
                  {
                     doc.malevolous_url += (input[i].getAttribute('name') + '=' + input[i].getAttribute('value') + '&');      /* otherwise give it a standard value */
                  }
               }
            }
            
            doc.malevolous_url = doc.malevolous_url.substr(0, (doc.malevolous_url.length - 1));                   /* normalize the malicious URL */            
            doc.malevolous_url = doc.malevolous_url.replace(/&/g, '%26');                                         
            doc.malevolous_url = doc.malevolous_url.replace(/ /g, '+');                                           
            send_injection_get();
         }
      }
}

/**********************************************************
*  function for retriving the document to be analyzed	  *
**********************************************************/

function get_homepage()
{
    xhr.open('POST', 'http://localhost:8083', false);                               
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");      
    xhr.send("url=" + doc._url);                                                    
    console.log('request sent for the url: ' + doc._url);
}

/***********************************************************************************
*  function for reading the action of the form and setting up the malicious link   *
***********************************************************************************/

function verify_action_dir(action)
{
   if(/[\/]$/.test(doc._url))                                        /* if the URL finish */
   {
      doc._url = doc._url.replace(/[\/]$/, '');
   }
   
   if(/^(\.\/)/.test(action))                                        // if the action start with "./" remove the dot
   {
      action = action.substr(1);
   }
   
   var count = (action.match(/\.\.\//g) || []).length;               /* store the number of '../' sequences in the action (if they exists) */
   
   if(count > 0)                                                     
   {
      action = action.replace(/\.\.\//g, '');                        /* remove all the '../' sequences */
         
      for(i = 0; i < count; i++)                                     /* for every '../' removed turn back by one position in the URL */
      {
         doc._url = doc._url.replace(/(\/[^\/]+)$/, "");             
      }
      doc._url = doc._url.replace(/([^\/]+)$/, "");                  /* remove the name of the actual dir of the URL  */
   }
   else
   {
      if(/^(\/\/)/.test(action))                                     // if the action start with "//" update that to a void string                         
      {
         doc._url = action.replace(/^(\/\/)/, '');
         action = '';
      }
      else
      {
         if(/#/.test(action))                                  // if the acation contain the fragment identifier, adjust the dir
         {
            var index = action.indexOf('#');
            action = action.substr(0, index);
            
            if(/^[\/]/.test(action))
            {
               action = '/' + (action);
            }
         
            doc._url = doc._url.replace(/([^\/]+)$/, "");          /* remove the name of the actual dir in the URL  */
         }
         else
         {
            if(/^((ftp:\/\/|http:\/\/|https:\/\/|www\.){1})/.test(action))                      // if the action is an entire URL, refresh the doc_url variable
            {
               doc._url = "";
            }
            else
            {
               if(/^[^\/]/.test(action))                                                        // if the action start with '/', thereby the endpoint is in the subsequent directory of the current one
               {
                  action = '/' + action;                                                        /* add '/' at the beginning of the URL */
               }
               else
               {
                  if(/(\/[^\/]+){1,30}/.test(action) || /(\/[^\/]+[\/]{1})/.test(action))        
                  {
                     var first_dir = action.match(/\/[^\/]+/g)[0];                              
                     var _index = doc._url.indexOf(first_dir);
                     
                     if(_index != -1)                                                           
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
*  function to verify if an input end up in the querystring		         *
*************************************************************************/

function is_sent(input)
{
    if(!input.getAttribute('type') || input.getAttribute('type') == 'text' || input.getAttribute('type') == 'search' || input.getAttribute('type') == 'hidden')
    {
       return true;
    }
    return false;
}

/**************************************************************************
*  function for verify  if the parameter can be used to inject javascript *
**************************************************************************/

function is_injectable(input)
{
   if(!input.getAttribute('type') || input.getAttribute('type') == 'text' || input.getAttribute('type') == 'search')
   {
       return true;
   }
   return false;
}


/**************************************************************************
* function to create the malicious url based on the available data		  *
**************************************************************************/

function make_malevolous_url(input, injection)
{
   doc.malevolous_url = doc._url + form_obj.form_action[l] + "?";                                                    
   console.log(doc._url + '     ' + form_obj.form_action[l]);
   
   for(i = 0; i < input.length; i++)                                                                                 
   {
      if(is_sent(input[i]))                                                                                          
      {
         if(is_injectable(input[i]))                                                                                 
         {
             doc.malevolous_url += (input[i].getAttribute('name') + "=" + injection + '&');                          
             report.vuln_input = input[i].getAttribute('name');
         }
         else
         {
            doc.malevolous_url += (input[i].getAttribute('name') + '=' + input[i].getAttribute('value') + '&');      
         }
      }
   }
   
   doc.malevolous_url = doc.malevolous_url.substr(0, (doc.malevolous_url.length - 1));                              
   doc.malevolous_url = doc.malevolous_url.replace(/&/g, '%26');                                         
   doc.malevolous_url = doc.malevolous_url.replace(/ /g, '+');                                          
}

/*****************************************************************************************
*  function to retrive the response within a possible JS injection						 *
*****************************************************************************************/

function send_injection_get()
{
   if(document.getElementById('type').value == 'simple')
    {make_malevolous_url(form_obj.input[l], doc.injection_2);}                   /* build the malicious URL for the form to be analyzed */
    xhr.open('POST', 'http://localhost:8083/injection_get', false);              /* send the request to the proxy */
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");   
    xhr.send("url=" + doc.malevolous_url);                                       
    console.log('injection_url_request_sent: ' + doc.malevolous_url);
    
    if(xhr.status === 403)                                                       /* if the HTTP response is 403(access denied) */
    {
      console.log("request blocked by firewall...");       						 /* update the report */
      report.waf = true;
    }
    else
    {
      doc.data_source = parser.parseFromString(xhr.responseText, "text/html");   /* retrieve the answer (parsing it to DOM object) */
      console.log("injection_data_retrived");
      doc.vaerifyInjection();                                                    /* verify if there is a successfull injection */
    }          
}
