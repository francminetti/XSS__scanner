                /* DINAMIC */                   /* javascript code for managing dynamic content of the page (report) */
                        
                                                   

var list_array = [];    /* array to keep memory of the urls in the list */

/*********************************************************************************************************
*   function for creating the url array and adding relative reprot spaces in the dom.				     *
*********************************************************************************************************/

function make_list()
{
    var button = document.getElementsByClassName('button')[0];                 /* momentarily disables the button to send data */
    button.setAttribute('disabled', 'true');
    
    var refresh_button = document.createElement('input');                                                /* creates and inserts in the DOM a button with which to refresh the page */
    refresh_button.setAttribute('type', 'button');
    refresh_button.setAttribute('value', "do another scan");
    refresh_button.setAttribute('onclick', "window.open('http://localhost:8083', '_self', false);");
    
    button.parentNode.appendChild(refresh_button);
    
    var list = document.getElementById('list');                             /* retrieves the textarea object from the DOM */
   
    var list_container = document.getElementById('report_container');       /* retrieves the div object (which will contain the reports) from the DOM */
    var i;                                                                  /* index of cicles */
    
    list_array = list.value.match(/([^\n]+\n)/g);                           /* save all the urls of the list in an array */
    
    if(list_array == null)
    {
        console.log('errore: lista di url vuota...');
    }
    
    for(i = 0; i < list_array.length; i++)                                  /* for each url of the list, insert the appropriate report space in the DOM */
    {
        list_container.innerHTML += ('<p class="url_report_container" id="url' + i + '">' + filter(list_array[i]) + '</p>');
    }
}


/*****************************************************************************************
*   function to filter 'special' input characters that will end up in HTML.				 *
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
*   function for changing the spaces related to vulnerable reports	     *
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
*   function for changing the spaces related to vulnerable reports          *
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
