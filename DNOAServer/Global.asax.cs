using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace DNOAServer
{
    // Note: For instructions on enabling IIS6 or IIS7 classic mode, 
    // visit http://go.microsoft.com/?LinkId=9394801

    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();

            WebApiConfig.Register(GlobalConfiguration.Configuration);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            AuthConfig.RegisterAuth();
        }

        public static List<ClientAuthorization> ClientAuthorizations = new List<ClientAuthorization>();

        public static List<RegisteredUser> RegisteredUsers = new List<RegisteredUser>() { 
                            new RegisteredUser{ ClientIdentifier="NATURE", Email="user1@alhambra.com", Password="login123"}, 
                            new RegisteredUser{ ClientIdentifier="NATURE", Email="user2@alhambra.com", Password="login123" } };

     
        public static RegisteredUser LoggedInUser
        {
            get { return RegisteredUsers.SingleOrDefault(user => user.Email == HttpContext.Current.User.Identity.Name); }
        }

    }

    public class RegisteredUser
    {
        public string Id { get; set; }
        public string ClientIdentifier { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class ClientAuthorization
    {
        public string User { get; set; }
        public string Client { get; set; }
        public HashSet<string> Scope { get; set; }
        public string Code { get; set; }
        public DateTime Expires { get; set; }
    }

}