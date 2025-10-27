
# MCP Server — University Demo

A practical demo showing how an AI Agent talks to an MCP Server with Asgardeo (OIDC) for secure login and policy-controlled actions. We built this on the MCP SDK after finding most off-the-shelf agents unstable for real demos. It’s designed for universities: browse courses, authenticate, and attempt enrollment under clear guardrails.

	•	Live Playground: https://ai-playground.choreoapps.dev/

	•	Repo: https://github.com/lpastor74/mcp-university-demo


What you’ll see

	•	Secure Auth (OIDC + PKCE via Asgardeo): Login before any action.
	•	Course Catalog & Enrollment: View available courses; request enrollment.
	•	Business Rules (demo):
	•	    Max 5 courses per semester.
	•	    No enrollment if there are unpaid dues from a prior term.
	•	Agent ↔ MCP flow: The agent queries tools; the server enforces policy.
	•	Choreo-ready: Deployed demo is hosted on Choreo; works locally too.

Architecture (at a glance)
comming soon

Prerequisites
	- Node.js 22.x (recommendation; resolves known npx/runner hiccups)
	- Asgardeo tenant & OIDC application (Authorization Code + PKCE)

	- Authorized redirect URLs (examples; adjust to your port):

	    http://localhost:*/oauth/callback
	    http://127.0.0.1:*/oauth/callback

Note: Some tools claim fixed-port config for local agents; results vary. This demo avoids that instability.

Quick Start (local)

	1.	Clone           
     git clone https://github.com/lpastor74/mcp-university-demo.git

     cd mcp-university-demo 

     2.	Configure
	•	Copy .env.example → .env and set:
	•	# DB connection
         MONGO_URI=mongodb://localhost:27017
         DB_NAME=university_demo

        # Transport-layer OAuth ON
        AUTH_ENABLED=true

        # Asgardeo tenant + OIDC
        TENANT=...
        AUTH_ISSUER=https://api.asgardeo.io/t/.../oauth2/token
        JWKS_URL=https://api.asgardeo.io/t/.../oauth2/jwks
        CLIENT_ID=__REPLACE_ME__
        ROLE_CLAIM_KEYS=roles,groups,app_roles,application_roles
        
        # TLS
        SSL_VERIFY=true
        # CA_BUNDLE=/path/to/corp-root.pem


    3.	Install & Run
    npm install
    npm run start   # or: npm run dev  (check package.json)      

    4.	Use the Demo
	•	Open the local URL.
	•	Sign in via Asgardeo.
	•	Browse courses; try to enroll.
	•	Observe rule enforcement (max 5/semester; no unpaid dues).

    5. AI agent  & Setup the Asgardeo App
    •   https://ai-playground.choreoapps.dev/
    
    6. Setup the Asgardeo App
    • create app (standard web based) 
    • save the client ID
    • configure the call back URL to your MCP server and allowed origins as well 
    (Wildcards should work un URL )
    • add https://ai-playground.choreoapps.dev/api/oauth/callback URL 
    • allow https://ai-playground.choreoapps.dev origins 
    • In Asgardeo need to have Student role so user can enroll in courses 
    • Additionaly you can setup the Academic and Finance role to create courses and manged the payment  
    

Configuration Tips

	•	Node version: If the MCP runner becomes unresponsive, ensure Node 22.x and remove old toolchains.    

    •  Notes (DB Requirement)

This demo requires a database. We use MongoDB to store courses and enrollments.

	•	Default DB name: university_demo
    
	•	Collections: courses, enrollments, studens