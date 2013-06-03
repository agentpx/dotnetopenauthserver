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

namespace DNOAServer.Controllers
{
    public class OAuth2Controller : Controller
    {
       

        public ActionResult Auth()
        {
            var authSvr = new AuthorizationServer(new AlhambraAuthorizationServerHost());

            var request = authSvr.ReadAuthorizationRequest(Request);
            Session["request"] = request;

            return View();
        }

        [HttpPost]
        public ActionResult Auth(LoginModel model)
        {

            var authSvrHostImpl = new AlhambraAuthorizationServerHost();

            if (model.UserName == "user1@nature.com" && model.Password == "login123")
            {
                var request = Session["request"] as EndUserAuthorizationRequest;
                var authSvr = new AuthorizationServer(authSvrHostImpl);
                var approval = authSvr.PrepareApproveAuthorizationRequest(request, model.UserName, new string[] { "openid" });

                return authSvr
                    .Channel
                    .PrepareResponse(approval).AsActionResult();
            }
            ViewBag.Message = "Wrong username or password!";

            return View();
        }

        public ActionResult Token()
        {
            var authSvr = new AuthorizationServer(new AlhambraAuthorizationServerHost());
            var response = authSvr.HandleTokenRequest(Request);
            return response.AsActionResult();
        }

    }
}
