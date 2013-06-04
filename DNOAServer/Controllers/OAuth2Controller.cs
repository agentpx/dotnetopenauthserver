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

namespace DNOAServer.Controllers
{
    public class OAuth2Controller : Controller
    {
        [AllowAnonymous]
        public ActionResult Auth()
        {
            var authSvr = new AuthorizationServer(new AlhambraAuthorizationServerHost());

            var request = authSvr.ReadAuthorizationRequest(Request);
            Session["request"] = request;

            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public ActionResult Auth(LoginModel model)
        {

            var authSvrHostImpl = new AlhambraAuthorizationServerHost();

            if ( (ModelState.IsValid) && (model.Email == "user1@alhambra.com" && model.Password == "login123"))
            {
               // FormsAuthentication.SetAuthCookie(model.Email, false);
                var request = Session["request"] as EndUserAuthorizationRequest;
                var authSvr = new AuthorizationServer(authSvrHostImpl);
                var approval = authSvr.PrepareApproveAuthorizationRequest(request, model.Email, new string[] { "openid" });

                return authSvr
                    .Channel
                    .PrepareResponse(approval).AsActionResult();
            }

            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "The user name or password provided is incorrect.");
            return View(model);

        }

        [AllowAnonymous]
        public ActionResult Token()
        {
            var authSvr = new AuthorizationServer(new AlhambraAuthorizationServerHost());
            
            var response = authSvr.HandleTokenRequest(Request);
            
            return response.AsActionResult();
        }

    }
}
