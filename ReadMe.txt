this is a little project i made for my university degree in the exam of web programming

this is a scanner for reflected xss vulnerabilities made with node.js(express), HTML, JS, and CSS.
this tool takes in input a list of URL via browser, retrive the HTML content of those and, if there are some attackable constructs(form GET)
he try to inject a scipt semantic value(payloads) in the parameters. 
At the end he analyzed the pages returned after the malicious GET call and by parsing the content returned with the browser DOM parser 
it enshure the presence or absence of the injected payload.

this tool is made up of 2 parts:

 - the server-side part, that is dedicated to send the HTTP requests for the pages to be retrived(made by express)
 - the browser-side part, that analyze the url list, the pages for seing if there are any attackable constructs, and the presence 
   or absence of a successfull injection in the returned page

the main reason for dividing the tool in 2 parts is that enable to bypass the SOP to retrive any pages to be further analyzed via browser.
the analysis via browser of the presence or absence of the bug is guaranteed by the browser parser.

node modules needed:

 - xmlhttprequest (npm install xmlhttprequest)
 - express (npm install express)

for using the tool:

 - in a console: node proxy_server.js
 - in the browser reach: localhost:8083
 - insert the url(s) you have to analyzed in the textarea(each one terminated by the '\n')
 - select the type of scan(simple or advanced)
 - launch the scan
 - see the output on the console of the proxy server, in the browser window and also in the console of the browser.

In the near future i would like to make a spider within the functionality of this tool, all written in PHP
