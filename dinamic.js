                /* DINAMIC */                   /* codice javascript per la gestione dei contenuti dinamici della pagnia(report) */
                        
                                                   

var list_array = [];    /* array per tenere in memoria gli url della lista */

/*********************************************************************************************************
*   funzione per la creazione dell' array di url e l'aggiunta nel dom dei relativi spazi dei reprot.     *
*********************************************************************************************************/

function make_list()
{
    var button = document.getElementsByClassName('button')[0];                 /* disabilita momentaneamente il bottone di invio dati */
    button.setAttribute('disabled', 'true');
    
    var refresh_button = document.createElement('input');                                                /* crea ed inserisce nel DOM un bottone con il quale fare il refresh della pagina */
    refresh_button.setAttribute('type', 'button');
    refresh_button.setAttribute('value', "effettua un'altra scansione");
    refresh_button.setAttribute('onclick', "window.open('http://localhost:8083', '_self', false);");
    
    button.parentNode.appendChild(refresh_button);
    
    var list = document.getElementById('list');                             /* recupera l'oggetto textarea dal DOM */
   
    var list_container = document.getElementById('report_container');       /* recupera l'oggetto div (che conterrà i report) dal DOM */
    var i;                                                                  /* indice dei cicli */
    
    list_array = list.value.match(/([^\n]+\n)/g);                           /* salva in un array tutti gli url nella lista */
    
    if(list_array == null)
    {
        console.log('errore: lista di url vuota...');
    }
    
    for(i = 0; i < list_array.length; i++)                                  /* per ogni url della lista insersci nel DOM l'opportuno spazio dei report */
    {
        list_container.innerHTML += ('<p class="url_report_container" id="url' + i + '">' + filter(list_array[i]) + '</p>');
    }
}


/*****************************************************************************************
*   funzione per filtrare caratteri 'speciali' in input che andranno a finire nell'HTML. *
*****************************************************************************************/

function filter(string)
{
    string = string.replace(/</g, '&lt;');
    string = string.replace(/>/g, '&gt;');
    string = string.replace(/"/g, '&quot;');
    string = string.replace(/'/g, '&apos;');
    string = string.replace(/&/g, '&amp;');
    return string;
}

/*************************************************************************
*   funzione per la modifica degli spazi relativi ai report vulnerablli  *
*************************************************************************/

function make_report(n, input_name)
{
    var id = 'url' + n;
    var id_2 = 'url' + (n + 1);
    
    var report_node = document.getElementById(id);
    var ref_node = document.getElementById(id_2);
   
    if(report_node.style.backgroundColor != "#8e1313")
    {
        report_node.style.backgroundColor = "#8e1313";
        report_node.style.cursor = "pointer";
        report_node.addEventListener('click', expand, false);
        var report_text = document.createElement('p');
        
        if(document.getElementById('type').value == 'simple')
        {
            report_text.innerHTML += ("l'applicazione è risultata vulnerabile ad xss reflected.<br/>il parametro vulnerabile è: " + input_name);
        }
        else
        {
            report_text.innerHTML += ("l'applicazione è risultata vulnerabile ad xss reflected.");
        }
        
        report_text.setAttribute('class', 'hide');
        
        document.getElementById('report_container').insertBefore(report_text, ref_node);
        
    }
    
}

/****************************************************************************
*   funzione che gstisce l'evento click sui report vulnerabili              *
****************************************************************************/

function expand()
{
    var node = this.nextSibling;
    
    if(node.getAttribute('class') == 'hide')
    {
        node.setAttribute('class', 'text_report_container');
    }
    else
    {
        node.setAttribute('class', 'hide');
    }
}
