/* jshint -W104, -W119, -W083 */
/*

                d8                           
        d88~\ _d88__ Y88b  / 888-~88e  888-~\
       C888    888    Y888/  888  888b 888   
        Y88b   888     Y8/   888  8888 888   
         888D  888      Y    888  888P 888   
       \_88P   "88_/   /     888-_88"  888   
                     _/      888             

          Copyright 2022 stypr ¯\_(ツ)_/¯
    https://github.com/stypr/advisories/LICENSE

*/

var dataLoadedComplete = false;
var vulnList = {};
var vulnKeywordList = {};

const cvss = new CVSS();
const input = document.querySelector("input[name='search']");
const verbose = document.querySelector("input[name='verbose']");

const generateRandomNumber = (min = 52, max = 235) => Math.floor(Math.random() * (max - min + 1) + min);

const generateRandomColor = () => {
    return `rgb(${ generateRandomNumber() }, ${ generateRandomNumber() }, ${ generateRandomNumber() })`;
};

const toggleOutput = (domName) => {
    if(document.querySelector("#detail-" + domName).classList.contains("d-none")){
        document.querySelector("#detail-" + domName).classList.remove("d-none");
    }else{
        document.querySelector("#detail-" + domName).classList.add("d-none");
    }
};

const getQueryVariable = (variable) => {
    // debugger;
    let query = window.location.search.substring(1);
    let vars = query.split('&');
    for (let i=0; i < vars.length; i++) {
        let pair = vars[i].split('=');
        if (decodeURIComponent(pair[0]) == variable) {
            return decodeURIComponent(pair[1]);
        }
    }
};

const updateCounter = async () => {
    /* Remove duplicate anycast prefixes */
    let domAdvisoryCounter = document.querySelector("#counter-advisory");
    domAdvisoryCounter.innerText = Object.keys(vulnList).length;
};

// Get current filters
const getFilterList = () => {
    let result = [];
    let list = document.querySelectorAll("button.active");
    for (let i in Object.keys(list)) {
        result.push([
            list[i].getAttribute("value-type"),
            list[i].getAttribute("value")
        ]);
    }
    return result;
}

const fetchFeed = async () => {
    let result = await fetch("/feed.json?" + generateRandomNumber(0, 2**32))
        .then((r) => r.json())
        .then((r) => {
            let save = location.hash;
            // Update vuln list and render output
            vulnList = updateVulnList(r);
            updateCounter();
        })
        .catch((r) => {
        });
    return result;
}

const updateVulnList = (response) => {
    for (let vulnId in response) {
        response[vulnId]['year'] = vulnId.split("-")[1];
        if (response[vulnId]['cvss']) {
            let cvssResult = generateScoreCVSS(response[vulnId]['cvss']);
            response[vulnId]['cvss_value'] = cvssResult[0];
            response[vulnId]['cvss_rating'] = cvssResult[1];
        }
    }
    return response;
};

// Generate CVSS 3.0 Score
const generateScoreCVSS = (value) => {
    try{
        let cvssValue = cvss.set(value);
        return [cvssValue[0], cvssValue[1]['name']];
    } catch(e) {
        console.log(e);
    }
};

const renderPolicy = async () => {
    
};

// Populate #result
const renderResultTable = async (response) => {
    let result = "";


    for (let vulnId in response) {
        let cvss_level = "";
        console.log(response[vulnId].cvss_rating);
        switch(response[vulnId].cvss_rating) {
            case "Critical": cvss_level = "text-bg-dark"; break;
            case "High": cvss_level = "text-bg-danger"; break;
            case "Medium": cvss_level = "text-bg-primary"; break;
            case "Low": cvss_level = "text-bg-secondary"; break;
            case "None": default: cvss_level = "text-bg-light"; break;
        }

        if(response[vulnId].secret){
            result += `
                <tr class="disable-hover" style="pointer-events: none;">
                    <td class="text-monospace text-end align-middle">
                        <b>${vulnId}</b><br>
                        ${response[vulnId].external_id ? response[vulnId].external_id : '&middot;&middot;&middot;'}
                    </td>
                    <td colspan=6 class="py-2 align-middle text-muted">
                        <svg class="bi" width="16" height="16">
                            <use xlink:href="/static/images/icon.stypr.svg#lock" />
                        </svg>
                        vendor or reporter disallowed the vulnerability disclosure.
                    </td>
                </tr>
            `;
            console.log(result);
        }else{
            result += `
                <tr style="cursor: pointer;" onclick="toggleOutput('${vulnId}')">
                    <td class="text-monospace text-end align-middle">
                        <b>${vulnId}</b><br>
                        ${response[vulnId].external_id ? response[vulnId].external_id : '&middot;&middot;&middot;'}
                    </td>
                    <td class="align-middle">
                        <span class="badge ${cvss_level} w-100">
                            ${response[vulnId].cvss_value}
                        </span>
                    </td>
                    <td class="align-middle">
                        <b>${response[vulnId].vendor}</b>
                        &middot; 
                        ${response[vulnId].product}
                    </td>
                    <td class="align-middle">
                        ${
                            response[vulnId].cwe.map(l => `
                                <span class="badge text-bg-secondary">${l}</span>
                            `).join("\n")
                        }
                    </td>
                    <td class="align-middle d-none d-sm-none d-md-table-cell d-lg-table-cell d-xl-table-cell">
                        ${response[vulnId].publish_date}
                    </td>
                </tr>
                <tr class="disable-hover d-none" id="detail-${vulnId}">
                    <td colspan="6" class="align-middle p-5" style="background: #fff !important;">
                        ${
                            response[vulnId].cvss ?
                            `
                                <h4>CVSS Score</h4>
                                <h6>
                                    <span class="badge ${cvss_level}">${response[vulnId].cvss_rating}</span>
                                    ${response[vulnId].cvss_value}
                                    <span class="cvss-value">(<a href="//nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=${response[vulnId].cvss}" target="_new">${response[vulnId].cvss}</a>)</span>
                                </h6>
                                <br>
                            `: ``
                        }
    
                        <h4>Affected Version</h4>
                        <ul>
                            ${
                                response[vulnId].affected_version.map(l => `
                                    <li>${l}</li>
                                `).join("\n")
                            }
                        </ul>
                        <p align="left">
                            Fixed in <b>${response[vulnId].fixed_version.join(", ")}</b>.
                        </p>

                        <br>
        
                        <h3>Description</h3>
                        <p align="left">
                            ${response[vulnId].description}
                        </p>
                        <br>
                        <h3>Reference</h3>
                        <ul style="overflow: hidden;">
                            ${
                                response[vulnId].reference.map(l => `
                                    <li><a href='${l}' style='white-space: wrap;'>${l}</a></li>
                                `).join("\n")
                            }
                        </ul>
                    </td>
                </tr>
            `;
        }
    }
    document.querySelector("#vuln-body").innerHTML = result;
};

const fetchDashboard = async (currentPage) => {
    document.querySelector("#loading-screen").classList.remove("d-none");
    document.querySelectorAll(".nav-scroller .nav-link").forEach(e => {
        e.classList.remove("active");
    });
    currentLink = document.querySelector(".nav-scroller .nav-link[href='#" + currentPage + "']");
    if (currentLink) {
        currentLink.classList.add("active");
    } else {
        currentLink = document.querySelector(".nav-scroller .nav-link[href='#advisory']");
        currentLink.classList.add("active");
    }

    await fetchFeed();
    dataLoadedComplete = true;

    document.querySelectorAll("[id^=page]").forEach(e => {
        e.classList.add("d-none");
    });

    switch (currentPage) {
        case "policy":
            document.querySelector("#page-policy").classList.remove("d-none");
            await renderPolicy();
            break;

        case "advisory":
        default:
            document.querySelector("#page-advisory").classList.remove("d-none");
            await renderResultTable(vulnList, false);
            break;
    }
    document.querySelector("#loading-screen").classList.add("d-none");
};

(() => {
    window.onhashchange = (event) => {
        if (!dataLoadedComplete) {
            return false;
        }
        let currentPage = location.hash.slice(1);
        fetchDashboard(currentPage);
    };
    fetchDashboard(location.hash.slice(1));
})();