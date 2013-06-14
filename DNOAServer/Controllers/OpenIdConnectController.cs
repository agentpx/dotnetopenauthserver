using DNOAServer.Code;
using DNOAServer.Models;
using DotNetOpenAuth.Messaging;
using DotNetOpenAuth.OAuth2;
using DotNetOpenAuth.OAuth2.Messages;
using Microsoft.IdentityModel.Tokens.JWT;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace DNOAServer.Controllers
{
    public class OpenIdConnectController : Controller
    {
    
        [AllowAnonymous]
        public ActionResult Auth(OpenIdConnectAuthorizationRequest request)
        {

            if (request.scope.Contains(OpenIdConnectScopes.OpenId) && !String.IsNullOrEmpty(request.client_id) && request.response_type=="code" && !String.IsNullOrEmpty(request.state) && !String.IsNullOrEmpty(request.redirect_uri) )
            {
                if (MvcApplication.registeredClients.Exists(x => x.Identifier == request.client_id))
                {
                    Session["AuthorizationRequest"] = request;

                    if (User.Identity.IsAuthenticated)
                    {
                        return RedirectToAction("AuthorizeExternalAccess");
                    }
                    else
                    {
                        return View();
                    }
                }
                else
                {
                    throw new HttpException((int)HttpStatusCode.Unauthorized, "This client id is not recognized");
                }
            }
            else
            {
                throw new HttpException((int)HttpStatusCode.BadRequest, "Request does not comply with OpenId Connect protocol");
            }
         
        }

        [AllowAnonymous]
        [HttpPost]
        public ActionResult Auth(LoginModel model)
        {

            if ((ModelState.IsValid) && (MvcApplication.registeredUsers.FirstOrDefault(x => x.Email == model.Email && x.Password == model.Password) != null))
            {

                FormsAuthentication.SetAuthCookie(model.Email, false);
                 
                return RedirectToAction("AuthorizeExternalAccess");
            }

            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "The user name or password provided is incorrect.");
            return View(model);

        }


        [Authorize]
        [HttpGet]
        public ActionResult AuthorizeExternalAccess()
        {
            //var pendingRequest = this.authorizationServer.ReadAuthorizationRequest(Request);

            var authorizationRequest = Session["AuthorizationRequest"] as OpenIdConnectAuthorizationRequest;

            if (authorizationRequest == null)
            {
                throw new HttpException((int)HttpStatusCode.BadRequest, "Missing authorization request.");
            }

            var requestingClient = MvcApplication.registeredUsers.FirstOrDefault(c => c.Email == User.Identity.Name);



            var model = new AlhambraOAuth2Authorization
            {
                UserId=User.Identity.Name,
                AuthorizedAt=DateTime.UtcNow,
                Scope = authorizationRequest.scope,
                AuthorizationRequest=authorizationRequest,
                State=authorizationRequest.state
            };

            MvcApplication.registeredAuthorizations.Add(model);
          
            return View(model);


        }

        [Authorize]
        [HttpPost]
        public ActionResult AuthorizeExternalAccessResponse(bool isApproved)
        {
            
            var authorizationRequest = Session["AuthorizationRequest"] as OpenIdConnectAuthorizationRequest;

            if (authorizationRequest == null)
            {
                throw new HttpException((int)HttpStatusCode.BadRequest, "Missing authorization request.");
            }
             
            if (isApproved)
            {
                var client = MvcApplication.registeredUsers.FirstOrDefault(c => c.Email == User.Identity.Name);

                string newCode = GenerateHexEncodedGUI();
                //register the new code and set the 'used' flag as false
                MvcApplication.codesGenerated.Add(newCode, false);

                Guid newAccessToken = Guid.NewGuid();
                Guid newRefreshToken = Guid.NewGuid();

                MvcApplication.tokensGenerated.Add(newAccessToken, newRefreshToken);
              
                var model = new AlhambraOAuth2Authorization { 
                    AccessToken=newAccessToken.ToString(),
                    RefreshToken=newRefreshToken.ToString(),
                    AuthorizationRequest=authorizationRequest ,
                    ExpiresAt = DateTime.Now.AddMinutes(2), 
                    AuthorizedAt=DateTime.UtcNow,
                    Scope = authorizationRequest.scope, 
                    UserId = client.Email, 
                    Code = newCode, 
                    State = authorizationRequest.state };

             

                var account = MvcApplication.registeredAuthorizations.FirstOrDefault(x =>  x.UserId == User.Identity.Name);
                //update existent info
                account.AccessToken = newAccessToken.ToString();
                account.RefreshToken = newRefreshToken.ToString();
                account.Code = newCode;
                
                
                account.ExpiresAt= DateTime.Now.AddMinutes(2);
                account.AuthorizedAt = DateTime.UtcNow;
                

                string url = authorizationRequest.redirect_uri + "?code=" + model.Code + "&state=" + model.State;
            
                return Redirect(url.ToString());

            }
            else
            {
            
                throw new HttpException((int)HttpStatusCode.Unauthorized, "Missing authorization request.");
            }

      
        }


        private string GenerateHexEncodedGUI()
        {
            Guid newGUID = Guid.NewGuid();
            StringBuilder buffer = new StringBuilder();
            foreach (Byte b in newGUID.ToByteArray())
            {
                buffer.AppendFormat("{0:X2}", b);
            }
            return buffer.ToString();
        }


        [AllowAnonymous] //because by now the client should have a valid CODE
        [HttpPost]
        public ActionResult Token(OpenIdConnectTokenRequest tokenRequest)
        {

            if (MvcApplication.codesGenerated.ContainsKey(tokenRequest.code)  && (tokenRequest.grant_type == "authorization_code"))
            {
                if (!MvcApplication.codesGenerated[tokenRequest.code])
                {
                    //you used it, now you flag it
                    MvcApplication.codesGenerated[tokenRequest.code] = true;

                    string issuer = Config.SERVER_ADDRESS;
                    string audience = MvcApplication.registeredAuthorizations.SingleOrDefault(x=>x.Code==tokenRequest.code).ClientIdentifier;
                    //By decision, the signature will not be included
                    //byte[] signature = AlhambraJwtTokenManager.GenerateSymmetricKeyForHmacSha256();

                    string subject = User.Identity.Name;
                    DateTime issuedAt = DateTime.UtcNow;
                    DateTime expires = DateTime.UtcNow.AddMinutes(2);

                    JWTSecurityToken jwt = AlhambraJwtTokenManager.GenerateJwtToken(issuer, subject, audience, expires);

                    string jwtReadyToBeSent = AlhambraJwtTokenManager.EncodeJWT(jwt);

                    OpenIdConnectToken token = new OpenIdConnectToken();

                    Guid newAccessToken = Guid.NewGuid();
                    Guid newRefreshToken = Guid.NewGuid();

                    MvcApplication.tokensGenerated.Add(newAccessToken, newRefreshToken);

                    token.access_token = newAccessToken.ToString();

                    token.expires_in = "120";
                    token.refresh_token = newRefreshToken.ToString();
                    token.id_token = jwtReadyToBeSent;
                    token.token_type = "Bearer";
                    string result = JsonConvert.SerializeObject(token);

                    return Content(result, "application/json");
                }
                else
                {
                    throw new HttpException((int)HttpStatusCode.Unauthorized, "This code has already been used");
                }
            }
            else
            {
                throw new HttpException((int) HttpStatusCode.BadRequest,"The request is not valid");
            }
        }

        [AllowAnonymous]
        public ActionResult UserInfo()
        {

            var authorizationRequest = Session["AuthorizationRequest"] as OpenIdConnectAuthorizationRequest;

            AlhambraOAuth2Authorization authorization = null;
            RegisteredUser registeredUser = null;

            if (HttpContext.Request.Headers["Authorization"].StartsWith("Bearer ", StringComparison.InvariantCultureIgnoreCase))
            {
                string accessToken = ASCIIEncoding.ASCII.GetString(Convert.FromBase64String(HttpContext.Request.Headers["Authorization"].Substring(7)));


                if (String.IsNullOrEmpty(accessToken))
                {
                    throw new HttpException((int)HttpStatusCode.Unauthorized, "The credentials are invalid");
                }

                if (!(MvcApplication.registeredAuthorizations.Exists(x => x.AccessToken == accessToken)))
                {
                    throw new HttpException((int)HttpStatusCode.Unauthorized, "The access token is invalid");
                }
                else
                {
                    authorization = MvcApplication.registeredAuthorizations.FirstOrDefault(x => x.AccessToken == accessToken);
                    registeredUser= MvcApplication.registeredUsers.FirstOrDefault(x=>x.Email==authorization.UserId);
                }
                
            }
            else
            {
                throw new HttpException((int)HttpStatusCode.Unauthorized, "The authorization request only supports Bearer Token Usage");
            }


            OAuth2Graph graph = new OAuth2Graph()
            {
                Id = registeredUser.Id
            };


            //use the scopes
             if(authorizationRequest.scope.Contains(OpenIdConnectScopes.OpenId)){
            foreach (string scope in authorizationRequest.scope.Split(' '))
            {
                switch (scope)
                {
                    case OpenIdConnectScopes.Profile:
                        graph.FirstName = registeredUser.FirstName;
                        graph.LastName = registeredUser.LastName;
                        graph.FullName = registeredUser.FullName;
                        graph.Profile = registeredUser.Profile;
                        graph.Email = registeredUser.Email;
                        break;
                    case OpenIdConnectScopes.Email:
                        graph.Email = registeredUser.Email;
                        break;
                    case OpenIdConnectScopes.FirstName:
                        graph.FirstName = registeredUser.FirstName;
                        break;
                    case OpenIdConnectScopes.LastName:
                        graph.FirstName = registeredUser.LastName;
                        break;
                }
            }
             }
             else
             {
                 throw new HttpException((int)HttpStatusCode.BadRequest, "The request is not valid");
             }
             
            string result = JsonConvert.SerializeObject(graph);
         

            return Content(result, "application/json");

        }
         


    }
}
