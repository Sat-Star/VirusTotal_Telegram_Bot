const TelegramBot = require('node-telegram-bot-api');
const { TELEGRAM_API, VIRUSTOTAL_API } = require('./keys'); //store the APIs in a keys.js file

const token = TELEGRAM_API;
const bot = new TelegramBot(token, { polling : true });
const api_url = 'https://www.virustotal.com/api/v3';

let chatId;

//now we'll define what the bot should do on /start

bot.onText(/\/start/, (msg) => {

    chatId = msg.chat.id;
    const resp = 'Hello welcome to SyntaxVirus bot\nSend a document to scan';

    bot.sendMessage(chatId, resp);
})

bot.on('text', (msg) => {
    if(msg.text.trim() !== '/start'){
        bot.sendMessage(chatId, 'Send a document/file to scan with VirusTotal');
    }
})

//now we'll define our paths to get response from the VirusTotal API

//our First step is to generate an upload link to upload the files to VirusTotal

const options = {
    method : 'GET',
    headers : {
        accept : 'application/json',
        'x-apikey' : VIRUSTOTAL_API
    }
};

fetch(`${api_url}/files/upload_url`, options)
    .then(response => response.json()) // converting response to JSON format
    .then(response => scanFile(response))
    .catch(error => console.log(error));

//now we'll define a function to upload the file to be scanned

function scanFile(response){

    const uploadUrl = response.data;

    bot.on('document', async (msg) => {
        const fileId = msg.document.file_id;

        const fileStream = bot.getFileStream(fileId);

        let buffer = []
        fileStream.on('data', chunk => {
            buffer.push(chunk);
        })

        fileStream.on('end', ()=>{
            const fileBuffer = Buffer.concat(buffer);
            const file = new File([fileBuffer], 'filename');

            const formData = new FormData();
            formData.append('file', file);


            //In the above code we retrieved the file uploaded to telegram and stored it in a formData
            //now we will send this formData to VirusTotal to analyse
            const options2 = {
                method : 'POST',
                headers : {
                    accept : 'application/json',
                    'x-apikey' : VIRUSTOTAL_API,
                },
                body : formData
            };

            fetch(uploadUrl, options2)
                .then(response => response.json())
                .then(response => getId(response))
                .catch(error => console.log(error));
        })
    })
}

//Now we'll define a function which will receive the analysis results from the VirusTotal API and send them to our Telegram Bot
let saveId;
function getId(response){
    saveId = response.data.id;
    scanResults();
}

function scanResults(){

    //Getting analysis data from API
    const options3 = {
        method : 'GET',
        headers : {
            accept : 'application/json',
            'x-apikey' : VIRUSTOTAL_API
        }
    };

    fetch(`${api_url}/analyses/${saveId}`, options3)
        .then(response => {
            if(!response.ok){
                throw new Error(`Failed to fetch scan results. Status : ${response.status}`);
            }
            return response.json();
        })
        .then(response => properFormat(response))
        .catch(err => console.log(err));
}

//We have received our response , now we just need to format it and display it in bot

function properFormat(response){
    if(response.data){
        console.log(response.data.attributes); //for debugging purposes
    }

    if(response.data.attributes.status === 'queued'){
        bot.sendMessage(chatId, 'Analysis is still queued. Please wait for a few minutes'); //waiting for response
        setTimeout(scanResults, 60000); //calling function after 1 minutes to recheck for response
    }

    else{
        const antiViruses = response.data.attributes.results;
        let res = "";
        for(let engine in antiViruses){
            const engineResult = antiViruses[engine].category;
            console.log(`${engine} : ${engineResult}`);
            
            res += `${engine} : ${engineResult}\n`; // appending the results to a string
        }
        
        if(res !== "")
        bot.sendMessage(chatId, res);

        const status = response.data.attributes.stats; //final status of the file scan

        let analysis = "";
        bot.sendMessage(chatId, 'Analysis Status : \n');
        for(let key in status){
            analysis += `${key} : ${status[key]}\n`;
        }

        bot.sendMessage(chatId, analysis);
    }
}
//the code is complete , now let's check if its working or not
