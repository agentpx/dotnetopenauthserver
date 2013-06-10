using DNOAServer.Models;
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

         

        public static List<RegisteredUser> registeredUsers = new List<RegisteredUser>() { 
                            new RegisteredUser{ Id="ALH0001", FirstName="John", LastName="Smith", Profile="Profile of John Smith", Email="user1@alhambra.com", Password="login123"}, 
                            new RegisteredUser{ Id="ALH0002", FirstName="Jane", LastName="Smith", Profile="Profile of Jane Smith", Email="user2@alhambra.com", Password="login123" }};
         
        public static List<AlhambraOAuth2Authorization> registeredAuthorizations = new List<AlhambraOAuth2Authorization>();

        public static List<AlhambraOAuth2Client> registeredClients = new List<AlhambraOAuth2Client>() { new AlhambraOAuth2Client{ Identifier="NATURE", Secret="login123"} };

        public static Dictionary<String, bool> codesGenerated = new Dictionary<string,bool>();

        public static Dictionary<Guid, Guid> tokensGenerated = new Dictionary<Guid, Guid>();

    }




}