// Graph API endpoint to show user profile
var graphApiEndpoint = "https://graph.microsoft.com/v1.0/me";

// Graph API scope used to obtain the access token to read user profile
var graphAPIScopes = ["https://graph.microsoft.com/user.read"];

// Initialize application
var userAgentApplication = new Msal.UserAgentApplication(msalconfig.clientID, null, loginCallback, {
    redirectUri: msalconfig.redirectUri
});

//Previous version of msal uses redirect url via a property
if (userAgentApplication.redirectUri) {
    userAgentApplication.redirectUri = msalconfig.redirectUri;
}

// Build query string from map of query parameter
function toQueryString(queryParams) {
    let encodedQueryParams = [];
    for (let key in queryParams) {
        encodedQueryParams.push(key + "=" + encodeURIComponent(queryParams[key]));
    }
    return encodedQueryParams.join("&");
}
// Converts decimal to hex equivalent
// (From ADAL.js: https://github.com/AzureAD/azure-activedirectory-library-for-js/blob/dev/lib/adal.js)
function _decimalToHex(number) {
    var hex = number.toString(16);
    while (hex.length < 2) {
        hex = '0' + hex;
    }
    return hex;
}
// Generates RFC4122 version 4 guid (128 bits)
// (From ADAL.js: https://github.com/AzureAD/azure-activedirectory-library-for-js/blob/dev/lib/adal.js)
function _guid() {
    // RFC4122: The version 4 UUID is meant for generating UUIDs from truly-random or
    // pseudo-random numbers.
    // The algorithm is as follows:
    //     Set the two most significant bits (bits 6 and 7) of the
    //        clock_seq_hi_and_reserved to zero and one, respectively.
    //     Set the four most significant bits (bits 12 through 15) of the
    //        time_hi_and_version field to the 4-bit version number from
    //        Section 4.1.3. Version4
    //     Set all the other bits to randomly (or pseudo-randomly) chosen
    //     values.
    // UUID                   = time-low "-" time-mid "-"time-high-and-version "-"clock-seq-reserved and low(2hexOctet)"-" node
    // time-low               = 4hexOctet
    // time-mid               = 2hexOctet
    // time-high-and-version  = 2hexOctet
    // clock-seq-and-reserved = hexOctet:
    // clock-seq-low          = hexOctet
    // node                   = 6hexOctet
    // Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    // y could be 1000, 1001, 1010, 1011 since most significant two bits needs to be 10
    // y values are 8, 9, A, B
    var cryptoObj = window.crypto || window.msCrypto; // for IE 11
    if (cryptoObj && cryptoObj.getRandomValues) {
        var buffer = new Uint8Array(16);
        cryptoObj.getRandomValues(buffer);
        //buffer[6] and buffer[7] represents the time_hi_and_version field. We will set the four most significant bits (4 through 7) of buffer[6] to represent decimal number 4 (UUID version number).
        buffer[6] |= 0x40; //buffer[6] | 01000000 will set the 6 bit to 1.
        buffer[6] &= 0x4f; //buffer[6] & 01001111 will set the 4, 5, and 7 bit to 0 such that bits 4-7 == 0100 = "4".
        //buffer[8] represents the clock_seq_hi_and_reserved field. We will set the two most significant bits (6 and 7) of the clock_seq_hi_and_reserved to zero and one, respectively.
        buffer[8] |= 0x80; //buffer[8] | 10000000 will set the 7 bit to 1.
        buffer[8] &= 0xbf; //buffer[8] & 10111111 will set the 6 bit to 0.
        return _decimalToHex(buffer[0]) + _decimalToHex(buffer[1]) + _decimalToHex(buffer[2]) + _decimalToHex(buffer[3]) + '-' + _decimalToHex(buffer[4]) + _decimalToHex(buffer[5]) + '-' + _decimalToHex(buffer[6]) + _decimalToHex(buffer[7]) + '-' +
            _decimalToHex(buffer[8]) + _decimalToHex(buffer[9]) + '-' + _decimalToHex(buffer[10]) + _decimalToHex(buffer[11]) + _decimalToHex(buffer[12]) + _decimalToHex(buffer[13]) + _decimalToHex(buffer[14]) + _decimalToHex(buffer[15]);
    }
    else {
        var guidHolder = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
        var hex = '0123456789abcdef';
        var r = 0;
        var guidResponse = "";
        for (var i = 0; i < 36; i++) {
            if (guidHolder[i] !== '-' && guidHolder[i] !== '4') {
                // each x and y needs to be random
                r = Math.random() * 16 | 0;
            }
            if (guidHolder[i] === 'x') {
                guidResponse += hex[r];
            } else if (guidHolder[i] === 'y') {
                // clock-seq-and-reserved first hex is filtered and remaining hex values are random
                r &= 0x3; // bit and with 0011 to set pos 2 to zero ?0??
                r |= 0x8; // set pos 3 to 1 as 1???
                guidResponse += hex[r];
            } else {
                guidResponse += guidHolder[i];
            }
        }
        return guidResponse;
    }
}

window.onload = function () {
    // If page is refreshed, continue to display user info
    microsoftTeams.initialize();
    microsoftTeams.getContext(function (context) {
        // Generate random state string and store it, so we can verify it in the callback
        let state = _guid();
        localStorage.setItem("simple.state", state);
        localStorage.removeItem("simple.error");

        // See https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols-implicit
        // for documentation on these query parameters
        let queryParams = {
            client_id: "6b8c33bd-4f8f-4ca4-998b-10c4f4147e21",
            response_type: "id_token token",
            response_mode: "fragment",
            resource: "https://graph.microsoft.com/",
            redirect_uri: window.location.origin + "/personal.html",
            nonce: _guid(),
            state: state,
            // login_hint pre-fills the username/email address field of the sign in page for the user, 
            // if you know their username ahead of time.
            login_hint: context.upn,
        };
        // Go to the AzureAD authorization endpoint
        let authorizeEndpoint = "https://login.microsoftonline.com/common/oauth2/authorize?" + toQueryString(queryParams);
        alert(authorizeEndpoint);
        window.location.assign(authorizeEndpoint);
    });

    if (!userAgentApplication.isCallback(window.location.hash) && window.parent === window && !window.opener) {
        var user = userAgentApplication.getUser();
        if (user) {
            callGraphApi();
        }
    }
}


/**
 * Call the Microsoft Graph API and display the results on the page
 */
function callGraphApi() {
    var user = userAgentApplication.getUser();
    if (!user) {
        
        // If user is not signed in, then prompt user to sign in via loginRedirect.
        // This will redirect user to the Azure Active Directory v2 Endpoint
        userAgentApplication.loginRedirect(graphAPIScopes);

        // The call to loginRedirect above frontloads the consent to query Graph API during the sign-in.
        // If you want to use dynamic consent, just remove the graphAPIScopes from loginRedirect call:
        // As such, user will be prompted to give consent as soon as the token for a resource that 
        // he/she hasn't consented before is requested. In the case of this application - 
        // the first time the Graph API call to obtain user's profile is executed.
    } else {

        // If user is already signed in, display the user info
        var userInfoElement = document.getElementById("userInfo");
        userInfoElement.parentElement.classList.remove("hidden");
        userInfoElement.innerHTML = JSON.stringify(user, null, 4);

        // Show Sign-Out button
        document.getElementById("signOutButton").classList.remove("hidden");

        // Now Call Graph API to show the user profile information:
        var graphCallResponseElement = document.getElementById("graphResponse");
        graphCallResponseElement.parentElement.classList.remove("hidden");
        graphCallResponseElement.innerText = "Calling Graph ...";

        // In order to call the Graph API, an access token needs to be acquired.
        // Try to acquire the token used to Query Graph API silently first
        userAgentApplication.acquireTokenSilent(graphAPIScopes)
            .then(function (token) {
                //After the access token is acquired, call the Web API, sending the acquired token
                callWebApiWithToken(graphApiEndpoint, token, graphCallResponseElement, document.getElementById("accessToken"));

            }, function (error) {
                // If the acquireTokenSilent() method fails, then acquire the token interactively via acquireTokenRedirect().
                // In this case, the browser will redirect user back to the Azure Active Directory v2 Endpoint so the user 
                // can re-type the current username and password and/ or give consent to new permissions your application is requesting.
                // After authentication/ authorization completes, this page will be reloaded again and callGraphApi() will be called.
                // Then, acquireTokenSilent will then acquire the token silently, the Graph API call results will be made and results will be displayed in the page.
                if (error) {
                    userAgentApplication.acquireTokenRedirect(graphAPIScopes);
                }
            });

    }
}

/**
 * Show an error message in the page
 * @param {string} endpoint - the endpoint used for the error message
 * @param {string} error - the error string
 * @param {object} errorElement - the HTML element in the page to display the error
 */
function showError(endpoint, error, errorDesc) {
    var formattedError = JSON.stringify(error, null, 4);
    if (formattedError.length < 3) {
        formattedError = error;
    }
    document.getElementById("errorMessage").innerHTML = "An error has occurred:<br/>Endpoint: " + endpoint + "<br/>Error: " + formattedError + "<br/>" + errorDesc;
    console.error(error);
}

/**
 * Callback method from sign-in: if no errors, call callGraphApi() to show results.
 * @param {string} errorDesc - If error occur, the error message
 * @param {object} token - The token received from login
 * @param {object} error - The error 
 * @param {string} tokenType - The token type: For loginRedirect, tokenType = "id_token". For acquireTokenRedirect, tokenType:"access_token"
 */
function loginCallback(errorDesc, token, error, tokenType) {
    if (errorDesc) {
        showError(msal.authority, error, errorDesc);
    } else {
        callGraphApi();
    }
}

/**
 * Call a Web API using an access token.
 * 
 * @param {any} endpoint - Web API endpoint
 * @param {any} token - Access token
 * @param {object} responseElement - HTML element used to display the results
 * @param {object} showTokenElement = HTML element used to display the RAW access token
 */
function callWebApiWithToken(endpoint, token, responseElement, showTokenElement) {
    var headers = new Headers();
    var bearer = "Bearer " + token;
    headers.append("Authorization", bearer);
    var options = {
        method: "GET",
        headers: headers
    };

    fetch(endpoint, options)
        .then(function (response) {
            var contentType = response.headers.get("content-type");
            if (response.status === 200 && contentType && contentType.indexOf("application/json") !== -1) {
                response.json()
                    .then(function (data) {
                        // Display response in the page
                        console.log(data);
                        responseElement.innerHTML = JSON.stringify(data, null, 4);
                        if (showTokenElement) {
                            showTokenElement.parentElement.classList.remove("hidden");
                            showTokenElement.innerHTML = token;
                        }
                    })
                    .catch(function (error) {
                        showError(endpoint, error);
                    });
            } else {
                response.json()
                    .then(function (data) {
                        // Display response as error in the page
                        showError(endpoint, data);
                    })
                    .catch(function (error) {
                        showError(endpoint, error);
                    });
            }
        })
        .catch(function (error) {
            showError(endpoint, error);
        });
}


/**
 * Sign-out the user
 */
function signOut() {
    userAgentApplication.logout();
}