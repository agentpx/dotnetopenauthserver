using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace DNOAServer
{
    public class BasicAuthentication : ActionFilterAttribute
    {


        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            try
            {
                if (String.IsNullOrEmpty(filterContext.HttpContext.Request.Headers["Authorization"]))
                {
                    filterContext.Result = new HttpUnauthorizedResult();
                }
                else
                {
                    if (filterContext.HttpContext.Request.Headers["Authorization"].StartsWith("Basic ", StringComparison.InvariantCultureIgnoreCase))
                    {
                        string[] credentials = ASCIIEncoding.ASCII.GetString(Convert.FromBase64String(filterContext.HttpContext.Request.Headers["Authorization"].Substring(6))).Split(':');

                        if (credentials.Length == 2)
                        {
                            if (String.IsNullOrEmpty(credentials[0]))
                            {
                                filterContext.Result = new HttpUnauthorizedResult();
                            }
                            else if (!(credentials[0] == "NATURE" && credentials[1] == "login123"))
                            {
                                filterContext.Result = new HttpUnauthorizedResult();
                            }
                        }
                        else
                        {
                            filterContext.Result = new HttpUnauthorizedResult();
                        }
                    }
                    else
                    {
                        filterContext.Result = new HttpUnauthorizedResult();
                    }
                }

                base.OnActionExecuting(filterContext);
            }
            catch
            {
                filterContext.Result = new HttpUnauthorizedResult();
            }
        }

    }
}