// Web Data Connector From Xray to Tableau
 
const config = {
    clientId: "0oa2zoorwstYHgpO44x7",
    redirectUri: "https://atlas-wdc-qa.azurewebsites.net/",
    authUrl: "https://dev-580656.okta.com/oauth2/default/v1",
    baseUrl: "https://xray-qa-api.azurewebsites.net/api/",
    version: "20210427",
}; 

// Called when web page first loads and when
// the OAuth flow returns to the page
//
// This function parses the auth code in the URI if available
$(document).ready(function() {
    const accessToken = isTokenValid(sessionStorage.getItem("access_token")) 
        ? sessionStorage.getItem("access_token")
        : isTokenValid(tableau.password) 
        ? tableau.password
        : null;

    updateUIWithAuthState(accessToken);

    const authCode = getAuthCode();        
    if (authCode && !accessToken) {
        getAccessToken(authCode);
    }

    $("#connectbutton").click(function() {
        doAuthRedirect();
    });
    
    $("#submitButton").click(function () {
        let scanId = document.getElementById("scanId").value;
        tableau.connectionData = JSON.stringify(
            {
                "baseUrl": config.baseUrl,
                "endpoint": "scans/" + scanId + "/recordCountByObject",
            }
        );
        tableau.connectionName = "Xray Data - scan: " + scanId;
        tableau.submit();
    });
});

// An on-click function for the connect to Xray API,
// This will redirect the user to an Okta login
async function doAuthRedirect() {
    if (!sessionStorage.getItem("code_verifier")) {
        await generatePKCEChallenge();
    }
    
    const url = config.authUrl + "/authorize"
                + "?client_id=" + config.clientId 
                + "&code_challenge=" + sessionStorage.getItem("code_challenge") 
                + "&code_challenge_method=S256" 
                + "&redirect_uri=" + encodeURI(config.redirectUri)
                + "&response_type=code"
                + "&state=CUbOZOUl7scZghOjraJ6SMUffH3ZZsr8EEQhpizplub856eM8GyUIVIcpkvGYtsf" // TODO
                + "&scope=openid%20offline_access";

    window.location.href = url;
}

function getAccessToken(authCode) {
    $.ajax({
        url: config.authUrl + "/token",
        type: "POST",
        headers: {
            "accept": "application/json",
            "cache-control": "no-cache",
            "content-type": "application/x-www-form-urlencoded"
        },
        processData: false,
        data: "grant_type=authorization_code" 
            + "&client_id=" + config.clientId 
            + "&redirect_uri=" + encodeURI(config.redirectUri)
            + "&code=" + authCode
            + "&code_verifier=" + sessionStorage.getItem("code_verifier")
            + "&scope=openid%20offline_access",
        success: function(data) {
            sessionStorage.setItem("access_token", data["access_token"]);       
            location.reload(); // Needed to trigger the storage of access token in tableau
        },
        error: function(xhr, error) {
            alert("Error: " + JSON.stringify(xhr.responseJSON.error) + "\n" + JSON.stringify(xhr.responseJSON.error_description));
            console.log("Error: " + JSON.stringify(xhr) + " " + error);
        }
    })
}

//------------- OAuth Helpers -------------//

// Checks whether an access token is still valid, removes the token if invalid
function isTokenValid(accessToken, deleteIfInvalid) {
    let isValid = false;
    if (accessToken) {
        let expiry;
        try {
            const decoded_token = jwt_decode(accessToken);
            expiry = decoded_token.exp * 1000;
        } catch (error) {
            console.log(error);
        } finally {
            if (new Date(expiry) > new Date()) {
                isValid = true;
                console.log("accessToken", accessToken);
            } else if (deleteIfInvalid) {
                tableau.password = null;
                sessionStorage.setItem("access_token", null);       
            }
        }
    }
    return isValid;
}

// This function toggles the label shown depending
// on whether or not the user has been authenticated
function updateUIWithAuthState(hasAuth) {
    console.log("updateUIWithAuthState, hasauth:", hasAuth);
    if (hasAuth) {
        $(".notsignedin").css("display", "none");
        $(".signedin").css("display", "block");
    } else {
        $(".notsignedin").css("display", "block");
        $(".signedin").css("display", "none");
    }
}

// Parses the auth code from the url
function getAuthCode() {
    const queryString = window.location.search;
    const urlParams = new URLSearchParams(queryString);
    const authCode = urlParams.get("code");
    return authCode;
}

// generates a PKCE challenge (code verifier and challenge)
async function generatePKCEChallenge() {
    sessionStorage.setItem("code_verifier", generateVerifier(50));
    sessionStorage.setItem("code_challenge", await pkce_challenge_from_verifier(sessionStorage.getItem("code_verifier")));
}

// Generates a code verifier
function generateVerifier(length) {
    let result = [];
    const mask = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    for ( let i = 0; i < length; i++ ) {
        result.push(mask.charAt(Math.floor(Math.random() * mask.length)));
    }
    return result.join("");
}

// Can't remember what this does
function sha256(plain) { 
    // returns promise ArrayBuffer
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return window.crypto.subtle.digest("SHA-256", data);
}

// Encodes the string
function base64urlencode(a) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(a)))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Computes a Code Challenge from a code verifier
async function pkce_challenge_from_verifier(v) {
    const hashed = await sha256(v);
    const base64encoded = base64urlencode(hashed);
    return base64encoded;
}


//------------- Tableau WDC code -------------//

// Create tableau connector, should be called first
let myConnector = tableau.makeConnector();

// Initial function called to check auth status and phase
myConnector.init = function(initCallback) {
    tableau.authType = tableau.authTypeEnum.custom;
    
    if (tableau.phase == tableau.phaseEnum.gatherDataPhase) {
        if (!isTokenValid(tableau.password, true)) {
            tableau.abortForAuth();
        }
    }
    
    const accessToken = sessionStorage.getItem("access_token");
    const hasAuth = isTokenValid(accessToken) || isTokenValid(tableau.password);
    updateUIWithAuthState(hasAuth);
    
    initCallback();
    
    // If we are not in the data gathering phase, we want to store the token
    // This allows us to access the token in the data gathering phase
    if (tableau.phase == tableau.phaseEnum.interactivePhase || tableau.phase == tableau.phaseEnum.authPhase) {
        if (hasAuth) {
            tableau.password = isTokenValid(accessToken) ? accessToken : tableau.password;

            if (tableau.phase == tableau.phaseEnum.authPhase) {
                // Auto-submit here if we are in the auth phase
                tableau.submit()
            }

            return;
        }
    }
}

// TODO implement refresh token storage when we can get a refresh token
// myConnector.setConnection = function(refresh_token, user_id, days) {
//     const connData = [refresh_token, user_id, days];
//     tableau.connectionData = JSON.stringify(connData);
//     tableau.connectionName = 'Fitbit Activity'; // name the data source. This will be the data source name in Tableau
//     tableau.submit();
// };

myConnector.getSchema = function (schemaCallback) {
    const cols = [{
        id: "scanId",
        dataType: tableau.dataTypeEnum.string
    }, {
        id: "name",
        dataType: tableau.dataTypeEnum.string
    }, {
        id: "apiName",
        dataType: tableau.dataTypeEnum.string
    }, {
        id: "type",
        dataType: tableau.dataTypeEnum.string
    }, {
        id: "recordCount",
        dataType: tableau.dataTypeEnum.int
    }, {
        id: "intensity",
        dataType: tableau.dataTypeEnum.float
    }, {
        id: "x",
        dataType: tableau.dataTypeEnum.int
    }, {
        id: "y",
        dataType: tableau.dataTypeEnum.int
    }];

    const tableSchema = {
        id: "xraySnapshot",
        alias: "Objects by record count",
        columns: cols
    };

    schemaCallback([tableSchema]);
};

myConnector.getData = function(table, doneCallback) {
    const connectionData = JSON.parse(tableau.connectionData);
    const url = connectionData.baseUrl + connectionData.endpoint;
    const access_token = tableau.password;

    $.ajax({
        url: url,
        dataType: "json",
        type: "GET",
        headers: {
            "Authorization": "Bearer " + access_token,
        },
        success: function(data) {
            let tableData = processData(data);    
            let row_index = 0;
            let size = 100;
            while (row_index < tableData.length){
                 table.appendRows(tableData.slice(row_index, size + row_index));
                 row_index += size;
                 tableau.reportProgress("Getting row: " + row_index);
            }
            doneCallback();
        },
        error: function(xhr, status, error) {
            if(xhr.responseJSON && xhr.responseJSON.message) {
                tableau.abortWithError("Error: " + JSON.stringify(xhr.responseJSON.message));
            } else {
                tableau.abortWithError("Error: " + JSON.stringify(xhr));
            }
        }
    });
};

function processData(data) {
    let tableData = [];
    
    let co_xx = 1;
    let co_yy = 1;
    let cs_xx = 1;
    let cs_yy = 1;

    // Iterate over the JSON object
    for (let i = 0, len = data.length; i < len; i++) {
        tableData.push({
            "id": data[i].id,
            "scanId": data[i].scanId,
            "name": data[i].name,
            "apiName": data[i].apiName,
            "type": data[i].type,
            "recordCount": data[i].recordCount
        });

        // Assign coordinates to custom objects
        if (data[i].type === "Custom Object") {
            tableData[tableData.length-1].x = co_xx;
            tableData[tableData.length-1].y = co_yy;
            if (co_yy < 31) {
                co_yy++;
            } else {
                co_xx++;
                co_yy = 1;
            }
        } else if (data[i].type === "Custom Setting" || data[i].type === "Custom Metadata") {
            tableData[tableData.length-1].x = cs_xx;
            tableData[tableData.length-1].y = cs_yy;
            if (cs_yy < 31) {
                cs_yy++;
            } else {
                cs_xx++;
                cs_yy = 1;
            }
        }
    }
    return tableData;
}

tableau.registerConnector(myConnector);