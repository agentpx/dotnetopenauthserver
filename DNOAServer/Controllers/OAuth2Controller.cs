using DNOAServer.Code;
using DNOAServer.Models;
using DotNetOpenAuth.OAuth2;
using DotNetOpenAuth.OAuth2.Messages;
using DotNetOpenAuth.OAuth2.AuthServer.Messages;
using DotNetOpenAuth.Mvc;
using DotNetOpenAuth.Messaging; // to call AsActionResult
using DotNetOpenAuth.AspNet.Clients;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using System.Net;
using Microsoft.IdentityModel.Tokens.JWT;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Runtime.Serialization.Json;
using System.IO;
using Newtonsoft.Json;

namespace DNOAServer.Controllers
{
    public class OAuth2Controller : Controller
    {

        private const string CLIENT_ADDRESS = "https://localhost:44301";
        private const string SERVER_ADDRESS = "https://localhost:44300";

        AuthorizationServer authorizationServer = new AuthorizationServer(new AlhambraAuthorizationServerHost());

        [AllowAnonymous]
        public ActionResult Auth()
        {
            
            var request = authorizationServer.ReadAuthorizationRequest(Request);
            Session["AuthorizationRequest"] = request;

            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public ActionResult Auth(LoginModel model)
        {

            if ( (ModelState.IsValid) && (MvcApplication.RegisteredUsers.FirstOrDefault(x=>x.Email==model.Email && x.Password==model.Password) != null))
            {
                
                FormsAuthentication.SetAuthCookie(model.Email, false);
                var authorizationRequest = Session["AuthorizationRequest"] as EndUserAuthorizationRequest;

                return RedirectToAction("AuthorizeExternalAccess");
            }

            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "The user name or password provided is incorrect.");
            return View(model);

        }

         
        //[Authorize]
        [HttpGet]
        public ActionResult AuthorizeExternalAccess()
        {
            //var pendingRequest = this.authorizationServer.ReadAuthorizationRequest(Request);

            var authorizationRequest = Session["AuthorizationRequest"] as EndUserAuthorizationRequest;

            if (authorizationRequest == null)
            {
                throw new HttpException((int)HttpStatusCode.BadRequest, "Missing authorization request.");
            }

            var requestingClient = MvcApplication.RegisteredUsers.FirstOrDefault(c => c.Email == User.Identity.Name);

           
          
            var model = new AccountAuthorizeModel
            {
                ClientApp = requestingClient.ClientIdentifier,
                Scope = authorizationRequest.Scope,
                AuthorizationRequest = authorizationRequest,
            };
          //  ViewBag.ReturnUrl = "AuthorizeExternalAccessResponse";
            return View(model);
         

        }

        //[Authorize]
        [HttpPost]
        public ActionResult AuthorizeExternalAccessResponse(bool isApproved)
        {

            var authorizationRequest = Session["AuthorizationRequest"] as EndUserAuthorizationRequest;

            if (authorizationRequest == null)
            {
                throw new HttpException((int)HttpStatusCode.BadRequest, "Missing authorization request.");
            }

            IDirectedProtocolMessage preparedResponse;

            OutgoingWebResponse outgoingWebResponse;

            if (isApproved)
            {
                var client = MvcApplication.RegisteredUsers.FirstOrDefault(c => c.ClientIdentifier == authorizationRequest.ClientIdentifier);

                preparedResponse = this.authorizationServer.PrepareApproveAuthorizationRequest(authorizationRequest, User.Identity.Name);

                outgoingWebResponse = this.authorizationServer.Channel.PrepareResponse(preparedResponse);
                
                string responseBody = outgoingWebResponse.Body;
                string parsedUrl = ExtractUrl(responseBody);
                string parsedCode = ExtractCodeFromUrl(new Uri(parsedUrl));

                MvcApplication.ClientAuthorizations.Add(new ClientAuthorization { Client = client.ClientIdentifier, Expires = DateTime.Now.AddMinutes(2), Scope = authorizationRequest.Scope, User = client.Email, Code="NOTHING" });
                  
            }
            else
            {
                preparedResponse = this.authorizationServer.PrepareRejectAuthorizationRequest(authorizationRequest);
                
            }

            outgoingWebResponse = this.authorizationServer.Channel.PrepareResponse(preparedResponse);

            return outgoingWebResponse.AsActionResult();

        }

 

        //[Authorize]
        public ActionResult Token()
        {
           
           // var authorizationRequest = Session["AuthorizationRequest"] as EndUserAuthorizationRequest;

            var response = authorizationServer.HandleTokenRequest(Request);
            
            //here you need to save the tokens for the specific user and client before sending it

            return response.AsActionResult();
        }

 
        public ActionResult UserInfo()
        {

            OAuth2Graph graph = new OAuth2Graph()
            {
                Id = "ALH0001",
                FirstName = "John",
                LastName = "Smith",
                FullName = "John M. Smith",
                Profile = "Profile of john smith",
                Email="john.smith@alhambra.com"
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

            return Content(result);

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
