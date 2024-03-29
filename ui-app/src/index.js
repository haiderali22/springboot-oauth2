import React, {useContext, useState} from 'react'
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';
import { AuthContext, AuthProvider, TAuthConfig, IAuthContext } from 'react-oauth2-code-pkce'

function LoginInfo() {

    // const [data,setData] = useState("");

   const { tokenData, token, login, logOut, idToken, error } = useContext(AuthContext)
    if (error) {
        return (
            <>
                <div style={{ color: 'red' }}>An error occurred during authentication: {error}</div>
                <button onClick={() => logOut()}>Logout</button>
            </>
        )
    }

    function setData(data){
        document.getElementById("dataDisplay").innerHTML = JSON.stringify(data);
    }

    const gatewayUrl = "http://localhost:8080";

    function callProductService() {
        let  headers = {};
        if(token){
            headers = { 'Authorization': `Bearer ${token}` };
        }

        fetch(`${gatewayUrl}/product/`, { headers })
            .then(response => response.json())
            .then(data => setData(data)).catch(error => {
            setData(error)
        });
    }

    return (
        <>
            {token ? (
                <>
                    <div>
                        <h4>Access Token (JWT)</h4>
                        <pre
                            style={{
                                width: '400px',
                                margin: '10px',
                                padding: '5px',
                                border: 'black 2px solid',
                                wordBreak: 'break-all',
                                whiteSpace: 'break-spaces',
                            }}
                        >
              {token}
            </pre>
                    </div>
                    <div>
                        <h4>Login Information from Access Token (Base64 decoded JWT)</h4>
                        <pre
                            style={{
                                width: '400px',
                                margin: '10px',
                                padding: '5px',
                                border: 'black 2px solid',
                                wordBreak: 'break-all',
                                whiteSpace: 'break-spaces',
                            }}
                        >
              {JSON.stringify(tokenData, null, 2)}
            </pre>
                    </div>
                    <button onClick={() => logOut()}>Logout</button>

                </>
            ) : (
                <>
                    <div>You are not logged in.</div>
                    <button onClick={() => login()}>Login</button>
                </>
            )}
            <br/>
            <button onClick={() => callProductService()}>Call Get Product</button>
            <br/>
            <label>Data</label>
            <pre id={"dataDisplay"}
                style={{
                    width: '400px',
                    margin: '10px',
                    padding: '5px',
                    border: 'black 2px solid',
                    wordBreak: 'break-all',
                    whiteSpace: 'break-spaces',
                }}
            >

            </pre>
        </>
    )
}

// const oauthServerUrl = 'http://192.168.10.7:8080/auth';
const oauthServerUrl = 'http://localhost:8081';

const authConfig = {
    clientId: 'web-client',
    authorizationEndpoint: `${oauthServerUrl}/oauth2/authorize`,
    logoutEndpoint: `${oauthServerUrl}/logout`,
    tokenEndpoint: `${oauthServerUrl}/oauth2/token`,
    redirectUri: 'http://127.0.0.1:3000',
    scope: 'openid',
    // Example to redirect back to original path after login has completed
    // preLogin: () => localStorage.setItem('preLoginPath', window.location.pathname),
    // postLogin: () => window.location.replace(localStorage.getItem('preLoginPath') || ''),
    decodeToken: false,
    autoLogin: false,
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
      <AuthProvider authConfig={authConfig}>
          <LoginInfo />
      </AuthProvider>
    <App />
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
