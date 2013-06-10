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
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace DNOAServer.Controllers
{
    public class OpenIdConnectController : Controller
    {
        private const string CLIENT_ADDRESS = "https://localhost:44301";
        private const string SERVER_ADDRESS = "https://localhost:44300";

       // AuthorizationServer authorizationServer = new AuthorizationServer(new AlhambraAuthorizationServerHost());

        [AllowAnonymous]
        public ActionResult Auth(OpenIdConnectAuthorizationRequest request)
        {
            var httpreq = Request;
            //var request = authorizationServer.ReadAuthorizationRequest(Request);
           Session["AuthorizationRequest"] = request;

           
           
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public ActionResult Auth(LoginModel model)
        {

            if ((ModelState.IsValid) && (MvcApplication.RegisteredUsers.FirstOrDefault(x => x.Email == model.Email && x.Password == model.Password) != null))
            {

                FormsAuthentication.SetAuthCookie(model.Email, false);
                 
                return RedirectToAction("AuthorizeExternalAccess");
            }

            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "The user name or password provided is incorrect.");
            return View(model);

        }


      //  [Authorize]
        [HttpGet]
        public ActionResult AuthorizeExternalAccess()
        {
            //var pendingRequest = this.authorizationServer.ReadAuthorizationRequest(Request);

            var authorizationRequest = Session["AuthorizationRequest"] as OpenIdConnectAuthorizationRequest;

            if (authorizationRequest == null)
            {
                throw new HttpException((int)HttpStatusCode.BadRequest, "Missing authorization request.");
            }

            var requestingClient = MvcApplication.RegisteredUsers.FirstOrDefault(c => c.Email == User.Identity.Name);



            var model = new AccountAuthorizeModelV2
            {
                UserId=User.Identity.Name,
                ClientIdentifier = requestingClient.ClientIdentifier,
                AuthorizedAt=DateTime.UtcNow,
                Scope = authorizationRequest.scope,
                AuthorizationRequest=authorizationRequest,
                State=authorizationRequest.state
            };

            MvcApplication.AccountAuthorizationsV2.Add(model);
          
            return View(model);


        }

     //   [Authorize]
        [HttpPost]
        public ActionResult AuthorizeExternalAccessResponse(bool isApproved)
        {

            var authorizationRequest = Session["AuthorizationRequest"] as OpenIdConnectAuthorizationRequest;

            if (authorizationRequest == null)
            {
                throw new HttpException((int)HttpStatusCode.BadRequest, "Missing authorization request.");
            }

           // IDirectedProtocolMessage preparedResponse;

           // OutgoingWebResponse outgoingWebResponse;

            if (isApproved)
            {
                var client = MvcApplication.RegisteredUsers.FirstOrDefault(c => c.ClientIdentifier == authorizationRequest.client_id);

                //preparedResponse = this.authorizationServer.PrepareApproveAuthorizationRequest(authorizationRequest, User.Identity.Name);

                //outgoingWebResponse = this.authorizationServer.Channel.PrepareResponse(preparedResponse);

               // string responseBody = outgoingWebResponse.Body;
               // string parsedUrl = ExtractUrl(responseBody);
               // string parsedCode = ExtractCodeFromUrl(new Uri(parsedUrl));
                var model = new AccountAuthorizeModelV2 { 
                    ClientIdentifier = client.ClientIdentifier, 
                    AccessToken="ACCESSTOKEN1",
                    RefreshToken="REFRESHTOKEN1",
                    AuthorizationRequest=authorizationRequest ,
                    ExpiresAt = DateTime.Now.AddMinutes(2), 
                    AuthorizedAt=DateTime.UtcNow,
                    Scope = authorizationRequest.scope, 
                    UserId = client.Email, 
                    Code = "CODE1", 
                    State = authorizationRequest.state };

               // MvcApplication.AccountAuthorizationsV2.Add(model);

                var account = MvcApplication.AccountAuthorizationsV2.FirstOrDefault(x => x.ClientIdentifier == client.ClientIdentifier && x.UserId == User.Identity.Name);

                account.AccessToken = "ACCESSTOKEN1";
                account.RefreshToken = "REFRESHTOKEN1";
                account.Code = "CODE1";
                account.ExpiresAt= DateTime.Now.AddMinutes(2);
                account.AuthorizedAt = DateTime.UtcNow;
                

                string url = authorizationRequest.redirect_uri + "?code=" + model.Code + "&state=" + model.State;
            
                return Redirect(url.ToString());

            }
            else
            {
               // preparedResponse = this.authorizationServer.PrepareRejectAuthorizationRequest(authorizationRequest);
                throw new HttpException((int)HttpStatusCode.Unauthorized, "Missing authorization request.");
            }

           // outgoingWebResponse = this.authorizationServer.Channel.PrepareResponse(preparedResponse);

           // return outgoingWebResponse.AsActionResult();
 

        }



      //  [Authorize]
        [HttpPost]
        public ActionResult Token(OpenIdConnectTokenRequest request)
        {

           
            string issuer = SERVER_ADDRESS;
            string audience = "NATURE";
            //By decision, the signature will not be included
           // byte[] signature = AlhambraJwtTokenManager.GenerateSymmetricKeyForHmacSha256();
            byte[] signature = null;
            string subject = User.Identity.Name;
            DateTime issuedAt = DateTime.UtcNow;
            DateTime expires = DateTime.UtcNow.AddMinutes(2);

            JWTSecurityToken jwt = AlhambraJwtTokenManager.GenerateJwtToken(issuer, subject, audience, expires);

            string jwtReadyToBeSent = AlhambraJwtTokenManager.EncodeJWT(jwt);
             


            OpenIdConnectToken token = new OpenIdConnectToken();
            token.access_token = "ACCESTOKEN1";
            token.expires_in = "120";
            token.refresh_token = "REFRESHTOKEN1";
            token.id_token = jwtReadyToBeSent;
            token.token_type = "Bearer";
            string result = JsonConvert.SerializeObject(token);
           
            return Content(result, "application/json");
             
        }


        public ActionResult UserInfo(string access_token)
        {
             
            var headers = Request.Headers;

            OAuth2Graph graph = new OAuth2Graph()
            {
                Id = "ALH0001",
                FirstName = "John",
                LastName = "Smith",
                FullName = "John M. Smith",
                Profile = "Profile of john smith",
                Email = "user1@alhambra.com"
            };


            //string issuer = SERVER_ADDRESS;
            //string audience = "NATURE";
            //By decision, the signature will not be included
            //byte[] signature = AlhambraJwtTokenManager.GenerateSymmetricKeyForHmacSha256();
            //string subject = "ALH0001";
            //DateTime issuedAt = DateTime.UtcNow;
            //DateTime expires = DateTime.UtcNow.AddMinutes(2);

            //JWTSecurityToken jwt = AlhambraJwtTokenManager.GenerateJwtToken(issuer, subject, audience, expires);

            //string jwtReadyToBeSent = AlhambraJwtTokenManager.EncodeJWT(jwt);

            //string jwtDecoded = AlhambraJwtTokenManager.DecodeJWT(jwt);

            // bool isJwtValid = AlhambraJwtTokenManager.IsTokenValid(jwt, audience, issuer);

            //  return Content(jwtDecoded.ToString() + "<br/><br/>" + jwtReadyToBeSent );


            //DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(OAuth2Graph));
            //MemoryStream stream1 = new MemoryStream();
            string result = JsonConvert.SerializeObject(graph);
            //serializer.WriteObject(stream1, graph);

            return Content(result, "application/json");

        }




        private string ExtractUrl(string htmlResponse)
        {

            int startIndexOfAnchor = htmlResponse.IndexOf(@"href=""");
            int endIndexOfAnchor = htmlResponse.IndexOf(@""">here");
            int lengthOfHtml = htmlResponse.Length;
            int lengthOfAnchor = endIndexOfAnchor - startIndexOfAnchor;
            string result = htmlResponse.Substring(startIndexOfAnchor + 6, lengthOfAnchor - 6);
            return result;
        }

        private string ExtractCodeFromUrl(Uri uri)
        {
            string query = uri.Query;
            int startIndexOfCode = query.IndexOf("code=");

            int startIndexOfState = query.IndexOf("state=");
            int lengthOfQuery = query.Length;
            string code = query.Substring(startIndexOfCode + 5, startIndexOfState - 1 - startIndexOfCode - 5);

            return code;
        }


    }
}
