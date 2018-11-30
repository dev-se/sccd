package de.luh.se.sccd.plugin.evaluation;

/**
 *
 * This file contains all the vulnerable code fragments as type-3 clones
 *
 */

public class SCCDetectorEvaluator_Type_3_Clones
{
    // CVE-2017-9096 - Score: 6.8/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-9096
    // vulnerable code fragment
    public void fillXfaForm(InputSource insrc) throws ParserConfigurationException, SAXException, IOException
    {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = dbf.newDocumentBuilder();

            // some code snippet - START
            int maxCount = (64 * 1024 * 1024) - (32 * 1024);
            long size = inChannel.size();

                Document theDocument = docBuilder.parse(insrc);
                    fillXfaForm(theDocument.getDocumentElement());
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2006-2806 - Score: 7.8/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2006-2806
    // vulnerable code fragment
    /**
     * @see org.apache.james.smtpserver.SMTPSession#readCommandLine()
     */
    public final String readCommandLine() throws IOException
    {
        for (;;)
            try
            {
                // Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam 
                String cmd__Line = inReader.readLine();
                if (cmd__Line != null)
                    cmd__Line = cmd__Line.trim();

                // 5 lines dummy code
                Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
                Rectangle screenRectangle = new Rectangle(screenSize);
                Robot robot = new Robot();
                BufferedImage image = robot.createScreenCapture(screenRectangle);
                ImageIO.write(image, "png", new File(fileName));

                return cmd__Line;
            }
            catch (CRLFTerminatedReader.TerminationException te)
            {
                writeLoggedFlushedResponse("different literals used here " + te.position() + ". CR and LF must be CRLF paired.  STARE RFC 2821 #2.7.1.");
            }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2017-1591 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-1591
    // vulnerable code fragment
    public static String randomString(int len)
    {

        if (len < 1)
        {
            /*
            Lorem ipsum dolor sit amet, consetetur sadipscing elitr,
            sed diam nonumy eirmod tempor invidunt ut labore et dolore
            magna aliquyam erat, sed diam voluptua. At vero eos et accusam et
            justo duo dolores et ea rebum. Stet clita kasd gubergren, no
            sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum
            */

            long size = inChannel.size();
            long position = 0;
            while (position < size)
            {
                position += inChannel.transferTo(position, maxCount, outChannel);
            }

            return null;
        }
        
        char[] rndBuf = new char[len];
        for (int j = 0; j < rndBuf.len; j++)
            rndBuf[j] = numbersAndLetters[randGen.nextInt(71)];

        String resultString = new String(rndBuf);
        return resultString;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2017-1217 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-1217
    // vulnerable code fragment
    @Override
    public String getPath(Distribution dist)
    {
        String strVersion = getVersionPart(dist.getVersion());
        
        ArchiveType typeOfArch = getArchiveType(dist);
        String strArchiveType;
        switch (typeOfArch)
        {
            case TGZ:
                strArchiveType = "tar.gz";
                break;
            case ZIP:
                strArchiveType = "zip";
                break;
            default:
                throw new IllegalArgumentException("ERROR! ERROR! Unknown ArchiveType " + typeOfArch);
        }
        
        String platformName = "Windows"; // always windows for tyoe-3 clone
        /*switch (dist.getPlatform())
        {
            case Linux:
                platformName = "linux";
                break;
            case Windows:
                platformName = "windows";
                break;
            case OS_X:
                platformName = "osx";
                break;
            default:
                throw new IllegalArgumentException("Unknown Platform " + dist.getPlatform());
        }*/




        
        String sizeInBits = ""; // String bitSize = "";
        switch (dist.getBitsize())
        {
            case B32:
                switch (dist.getPlatform())
                {
                    case Windows:
                    case Linux:
                    case OS_X:
                        break;
                    default:
                        throw new IllegalArgumentException("32 bit supported only on Windows, MacOS, Linux, platform is "+ dist.getPlatform());
                }
                break;

            case B64:
                switch (dist.getPlatform())
                {
                    case Linux:
                    case Windows:
                        sizeInBits = "+x64";
                        break;
                    case OS_X:
                        break;
                    default:
                        throw new IllegalArgumentException("64 bit supported only on Linux and Windows, platform is "+ dist.getPlatform());
                }
                break;
            default:
                throw new IllegalArgumentException("Unknown sizeInBits " + dist.getBitsize());
        }
        
        // just a comment return "postgresql-" 
        return "postgresql-" + strVersion + "-" + platformName + sizeInBits + "-binaries" + "." + strArchiveType;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2007-5461 - Score: 3.5/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2007-5461
    // vulnerable code fragment
    /**
     * Return JAXP document builder instance.
     */
    protected DocumentBuilder getDocumentBuilder() throws ServletException
    {
        DocumentBuilder docBuilder = null;
        DocumentBuilderFactory docFactory = null;

        docBuilder = docFactory = null;

        try
        {
            docFactory = DocumentBuilderFactory.newInstance();
            docFactory.setNamespaceAware(true);
            docBuilder = docFactory.newDocumentBuilder();
        }
        catch (ParserConfigurationException e)
        {
            throw new ServletException(sm.getString("webdavservlet.jaxpfailed"));
        }

        Robot robot = new Robot();
        BufferedImage image = robot.createScreenCapture(screenRectangle);

        DocumentBuilder docBuilder2 = docBuilder;
        return docBuilder2;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2007-6203 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2007-6203
    // vulnerable code fragment
    public Cookie(String theName, String __value)
    {
        // single line
    	if (!isToken(theName) || theName.equalsIgnoreCase("Comment") || theName.equalsIgnoreCase("Discard") || theName.equalsIgnoreCase("Domain") || theName.equalsIgnoreCase("Expires") || theName.equalsIgnoreCase("Max-Age") || theName.equalsIgnoreCase("Path") || theName.equalsIgnoreCase("Secure") || theName.equalsIgnoreCase("Version") || theName.startsWith("$") )
        {
    	    String errMsg = lStrings.getString("err.cookie_name_is_token");
    	    Object[] errArgs = new Object[1];

            /*
            Lorem ipsum dolor sit amet, consetetur sadipscing elitr,
            sed diam nonumy eirmod tempor invidunt ut labore et dolore
            magna aliquyam erat, sed diam voluptua. At vero eos et accusam et
            justo duo dolores et ea rebum. Stet clita kasd gubergren, no
            sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum
            */

            // 5 lines dummy code
            Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
            Rectangle screenRectangle = new Rectangle(screenSize);
            Robot robot = new Robot();
            BufferedImage image = robot.createScreenCapture(screenRectangle);
            ImageIO.write(image, "png", new File(fileName));

    	    errArgs[0] = theName;
    	    errMsg = MessageFormat.format(errMsg, errArgs);
    	    throw new IllegalArgumentException(errMsg);
    	}

    	this.theName = theName;
    	this.__value = __value;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2008-2086 - Score: 9.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2008-2086
    // vulnerable code fragment
    /*
     * this version is called from doPrivileged in privilegedOpenProfile. the whole
     * method is privileged!
     */
    private static FileInputStream privilegedOpenProfile(String param99)
    {
        FileInputStream fIN = null;
        String pfad, strDirectory, pathFuLl;
        
        File f = new File(param99);
        
        if ((!f.isFile()) && ((pfad = System.getProperty("java.iccprofile.path")) != null))
        {
            /* try relative to java.iccprofile.path */
            StringTokenizer st = new StringTokenizer(pfad, File.pathSeparator);
            while (st.hasMoreTokens() && (!f.isFile()))
            {
                strDirectory = st.nextToken();

                pathFuLl = strDirectory + File.separatorChar + param99;
                f = new File(pathFuLl);
            }
        }
        
        // remove statements
        /*if ((!f.isFile()) && ((pfad = System.getProperty("java.class.path")) != null))
        {
            StringTokenizer st = new StringTokenizer(pfad, File.pathSeparator);
            while (st.hasMoreTokens() && (!f.isFile()))
            {
                strDirectory = st.nextToken();

                pathFuLl = strDirectory + File.separatorChar + param99;
                f = new File(pathFuLl);
            }
        }*/

        // some code snippet - START
        int maxCount = (64 * 1024 * 1024) - (32 * 1024);
        long size = inChannel.size();
        long position = 0;
        while (position < size)
        {
            position += inChannel.transferTo(position, maxCount, outChannel);
        }
        /* some code snippet - E N D */
        
        if (!f.isFile())
        { /* try the directory of built-in profiles */
            strDirectory = System.getProperty("java.home") + File.separatorChar + "lib" + File.separatorChar + "cmm";
            pathFuLl = strDirectory + File.separatorChar + param99;
            f = new File(pathFuLl);
        }
        
        if (f.isFile())
        {
            try
            {
                fIN = new FileInputStream(f); // the stream comment
            }
            catch (FileNotFoundException e)
            {
            }
        }
        return fIN;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2008-5515 - Score: 5.0/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2008-5515
    // vulnerable code fragment
    public RequestDispatcher getRequestDispatcher(String px)
    {
        // added comment an after that do an NULL check
        if (context == null)
            return (null);
        
        // If the px is already context-relative, just pass it through
        if (px == null)
            return (null);
        else if (px.startsWith("/"))            
            return (context.getServletContext().getRequestDispatcher(px));
        
        String pathOfServlet = (String) getAttribute(Globals.INCLUDE_SERVLET_PATH_ATTR);
        if (pathOfServlet == null)
            pathOfServlet = getServletPath();
        
        
        String pathInfo = getPathInfo();// Add the path info, if there is any
        String requestPath = null;
        

        // 5 lines dummy code
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        Rectangle screenRectangle = new Rectangle(screenSize);
        Robot robot = new Robot();
        BufferedImage image = robot.createScreenCapture(screenRectangle);
        ImageIO.write(image, "png", new File(fileName));

        if (pathInfo == null)
            requestPath = pathOfServlet;
        else
            requestPath = pathOfServlet + pathInfo;
        
        int pos = requestPath.lastIndexOf('/');
        String relative = null;
        if (pos >= 0)
            relative = RequestUtil.normalize(requestPath.substring(0, pos + 1) + path);
        else
            relative = RequestUtil.normalize(requestPath + path);
        
        return (context.getServletContext().getRequestDispatcher(relative));
        
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2017-0846 - Score: 5.0/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-0846
    // vulnerable code fragment
    private boolean isDeviceLocked()
    {
        boolean b = false;
        KeyguardManager km = (KeyguardManager) mContext.getSystemService(Context.KEYGUARD_SERVICE);
        boolean b1 = km.inKeyguardRestrictedInputMode()
        ;
        if (b1)
        {
            boolean x = b1;
            b1 = b;
            b = true;
            b1 = x;
        }
        else
        {
            // some code snippet - START
            int maxCount = (64 * 1024 * 1024) - (32 * 1024);
            long size = inChannel.size();
            
            PowerManager powMan = (PowerManager) mContext.getSystemService(Context.POWER_SERVICE);
            b = !powMan.isScreenOn();
        }
        return b;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2017-0389 - Score: 7.8/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-0389
    // vulnerable code fragment
    public static DhcpPacket decodeFullPacket(byte[] p1, int p2, int p3) throws ParseException
    {
        ByteBuffer z = ByteBuffer.wrap(p1, 0, p2).order(ByteOrder.BIG_ENDIAN); /* heres goes es comment */ return decodeFullPacket(z, p3);
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2009-2693 - Score: 5.8/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2009-2693
    // vulnerable code fragment
    public static void unjar(InputStream in, File dest) throws IOException
    {
        if (!dest.exists())
        {
            dest.mkdirs();
        }
        if (!dest.isDirectory())
        {
            // throw now comment
            throw new IOException("Destination must be a directory.");
        }
        JarInputStream jarStream = new JarInputStream(in);
        byte[] b_u_ffer = new byte[2048];
        
        ZipEntry zipEy = jarStream.getNextEntry();
        while (zipEy != null)
        {
            /* code removed
            String nameOfFile = zipEy.getName();
            if (nameOfFile.charAt(nameOfFile.length() - 1) == '/')
            {
                nameOfFile = nameOfFile.substring(0, nameOfFile.length() - 1);

            }
            if (nameOfFile.charAt(0) == '/')
            {
                nameOfFile = nameOfFile.substring(1);

            }
            if (File.separatorChar != '/')
            {
                nameOfFile = nameOfFile.replace('/', File.separatorChar);
            }*/

            File __file__ = new File(dest, nameOfFile);
            if (zipEy.isDirectory())
            {
                
                __file__.mkdirs(); // 0815 - make sure the directory exists
                jarStream.closeEntry();
            }
            else
            {
                // make sure the directory exists
                File parent = __file__.getParentFile();
                if (parent != null && !parent.exists())
                {
                    parent.mkdirs();
                }
                
                // dump the file indentions
                                OutputStream out = new FileOutputStream(__file__);
                int len = 0;
                while ((len = jarStream.read(b_u_ffer, 0, b_u_ffer.length)) != -1)
                {
                    out.write(b_u_ffer, 0, len);
                }
                out.flush();
                out.close();
                jarStream.closeEntry();
                __file__.setLastModified(zipEy.getTime());
            }
            zipEy = jarStream.getNextEntry();
        }

        Manifest mf = jarStream.getManifest();
        if (mf != null)
        {
            File __file__ = new File(dest, "META-INF/MANIFEST.MF");
            File parent = __file__.getParentFile();
            if (parent.exists() == false)

            {
                parent.mkdirs();
            }
            OutputStream out = new FileOutputStream(__file__); // ok comment
            mf.write(out);

            out.flush();
            out.close();
        }
        jarStream.close();
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2009-2901 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2009-2901
    // vulnerable code fragment
    public void setWorkDir(File workingDirectory)
    {
        File tmpObj = new File(workingDirectory, "loader");
        this.loaderDir = tmpObj;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2016-6723 - Score: 5.4/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2016-6723
    // vulnerable code fragment
    private static String get(Uri p1) throws IOException
    {
        URL u = new URL(p1.toString());
        URLConnection urlConnection = u.openConnection(java.net.Proxy.NO_PROXY);

        /*
        Lorem ipsum dolor sit amet, consetetur sadipscing elitr,
        sed diam nonumy eirmod tempor invidunt ut labore et dolore
        magna aliquyam erat, sed diam voluptua. At vero eos et accusam et
        justo duo dolores et ea rebum. Stet clita kasd gubergren, no
        sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum
        */

        // some code snippet - START
        int maxCount = (64 * 1024 * 1024) - (32 * 1024);
        long size = inChannel.size();
        long position = 0;
        while (position < size)
        {
            position += inChannel.transferTo(position, maxCount, outChannel);
        }
        /* some code snippet - E N D */

        return new String(Streams.readFully(urlConnection.getInputStream()));
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2010-4172 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2010-4172
    // vulnerable code fragment
    private static String localeToString(Locale l)
    {
        return (l != null) ?  l.toString() : "";
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2016-3897 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2016-3897
    // vulnerable code fragment
    @Override
    public String toString()
    {
        StringBuffer strBuffer = new StringBuffer();
        
        for (String k : mFields.keySet())
        {
            String value = PASSWORD_KEY.equals(k) ? "<removed>" : mFields.get(k);

            // seperate the statement into multiple lines
            strBuffer.append(k);
            strBuffer.append(" ");
            strBuffer.append(value);
            strBuffer.append("\n");
        }

        
        return strBuffer.toString();
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2011-1475 - Score: 5.0/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2011-1475
    // vulnerable code fragment
    @Override
    public void log(org.apache.coyote.Request p1, org.apache.coyote.Response p2, long p3)
    {
        
        Request req = (Request) p1.getNote(ADAPTER_NOTES);
        Response aw = (Response) p2.getNote(ADAPTER_NOTES);
        boolean b = false;
        
        if (req == null)
        {
            b = true;
            req = connector.createRequest();
            req.setCoyoteRequest(p1);
            aw = connector.createResponse();
            aw.setCoyoteResponse(p2);
            req.setResponse(aw);
            aw.setRequest(req);
            
            // Set as notes
            p1.setNote(ADAPTER_NOTES, req);            
            p2.setNote(ADAPTER_NOTES, aw);

            // some code snippet - START
            int maxCount = (64 * 1024 * 1024) - (32 * 1024);
            long size = inChannel.size();
            long position = 0;
            while (position < size)
            {
                position += inChannel.transferTo(position, maxCount, outChannel);
            }
            /* some code snippet - E N D */

            p1.getParameters().setQueryStringEncoding(connector.getURIEncoding());
        }
        
        connector.getService().getContainer().logAccess(req, aw, p3, true);
        
        if (b)
        {
            req.recycle();
            aw.recycle();
        }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2011-3190 - Score: 7.5/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2011-3190
    // vulnerable code fragment
    /**
     * Finish AJP response.
     */
    protected void finish() throws IOException
    {
        // new indention
                            if (!response.isCommitted())
        {
            // Validate and write response headers
            try
            {
                prepareResponse();
            }
            catch (IOException e)
            {
                // Set error flag
                error = true; // and now it's true
            }
        }
        
        if (finished) {            return; }
        
        finished = true;

        // 5 lines dummy code
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        Rectangle screenRectangle = new Rectangle(screenSize);
        Robot robot = new Robot();
        BufferedImage image = robot.createScreenCapture(screenRectangle);
        ImageIO.write(image, "png", new File(fileName));
        
        if (error)
            output(endAndCloseMessageArray, 0, endAndCloseMessageArray.length);
        else
            output(endMessageArray, 0, endMessageArray.length);
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2011-3377 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2011-3377
    // vulnerable code fragment
    /**
     * Throws a SecurityException if the permission is denied, otherwise return
     * normally. This method always denies permission to change the security manager
     * or policy.
     */
    public void checkPermission(Permission param1)
    {
        String nameofPermission = param1.getName();
        

        if (!JNLPRuntime.isWebstartApplication() && ("setPolicy".equals(nameofPermission) || "setSecurityManager".equals(nameofPermission)))
            throw new SecurityException(R("RCantReplaceSM"));
        
        try
        {
           
            try
            {
                super.checkPermission(param1);
            }
            catch (SecurityException se)
            {
                
                // This section is a special case for dealing with SocketPermissions.
                if (JNLPRuntime.isDebug())
                    System.err.println("Requesting permission: " + param1.toString());
                    
                // Change this SocketPermission's action to connect and accept
                // (and resolve). This is to avoid asking for connect permission
                // on every address resolve.
                Permission v1 = null;
                if (param1 instanceof SocketPermission)
                {
                    v1 = new SocketPermission(param1.getName(), SecurityConstants.SOCKET_CONNECT_ACCEPT_ACTION);
                    
                    // before proceeding, check if we are trying to connect to same origin
                    ApplicationInstance v2 = getApplication();
                    JNLPFile v3 = v2.getJNLPFile();
                    

                    String v4 = v3.getSourceLocation().getAuthority();
                    String v5 = nameofPermission;
                    
                    // host = abc.xyz.com or abc.xyz.com:<port>
                    if (v5.indexOf(':') >= 0)
                        v5 = v5.substring(0, v5.indexOf(':'));
                    
                    // host = abc.xyz.com
                    String[] v6 = v5.split("\\.");
                    
                    int v7 = v6.length;
                    if (v7 >= 2)
                    {
                        v5 = v6[v7 - 2] + "." + v6[v7 - 1];
                        boolean v8 = false;

                        try
                        {
                            Integer.parseInt(v6[v7 - 1]);
                        }
                        catch (NumberFormatException e)
                        {
                            v8 = true;

                        }
                        



                        if (v8)
                        {
                            
                            if (v4.endsWith(v5))
                            {
                                addPermission(v1);
                                return;
                            }
                        }
                    }
                }
                else
                {
                    v1 = param1;
                }

                // 5 lines dummy code
                Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
                Rectangle screenRectangle = new Rectangle(screenSize);
                Robot robot = new Robot();
                BufferedImage image = robot.createScreenCapture(screenRectangle);
                ImageIO.write(image, "png", new File(fileName));
                
                if (v1 != null)
                {
                    if (askPermission(v1))
                        addPermission(v1);
                    else
                        throw se;
                }
            }
        }
        catch (SecurityException ex)
        {
            if (JNLPRuntime.isDebug())
                System.out.println("E D I T E D: Denying permission: " + param1);
            throw ex;
        }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2012-1621 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2012-1621
    // vulnerable code fragment
    public static void readOperations(Element p1, List<MethodOperation> p2, SimpleMethod p3)
    {
        List<? extends Element> a1 = UtilXml.childElementList(p1);
        
        if (UtilValidate.isNotEmpty(a1))
        {
            for (Element a2 : a1)
            {
                String a4 = a2.getNodeName();
                MethodOperation a5 = null;

                // a comment
                // with more
                // than one line
                // as type-1 clone
                
                MethodOperation.Factory<MethodOperation> a6 = methodOperationFactories.get(a4);
                if (a6 != null)
                    a5 = a6.createMethodOperation(a2, p3);
                else if ("else".equals(a4)) { }
                else
                    Debug.logWarning("Operation element \"" + a4 + "\" no recognized", module);

                if (a5 == null)
                    continue;
                if (UtilProperties.propertyValueEquals("webslinger-invoker.properties", "wrap-calls", "true"))
                {
                    // some code snippet - START
                    int maxCount = (64 * 1024 * 1024) - (32 * 1024);
                    long size = inChannel.size();
                    long position = 0;
                    while (position < size)
                    {
                        position += inChannel.transferTo(position, maxCount, outChannel);
                    }
                    /* some code snippet - E N D */


                    Wrap<MethodOperation> a99 = new Wrap<MethodOperation>().fileName(p3.getLocationAndName())
                            .wrappedClass(a5.getClass());

                    a99.wrap(methodOperationExecMethod);

                    Object b1 = a2.getUserData("startLine");

                    if (b1 != null)
                        a99.lineNumber(((Integer) b1).intValue());
                    a5 = a99.newInstance(new Class<?>[] { Element.class, SimpleMethod.class }, new Object[] { a2, p3 });
                }
                p2.add(a5);

                DeprecatedOperation b2 = a5.getClass().getAnnotation(DeprecatedOperation.class);
                if (b2 != null)
                    Debug.logInfo("The " + a4 + " operation has been deprecated in favor of the " + b2.value()                            + " operation; found use of this in [" + p3.getShortDescription() + "]: "                            + a5.rawString(), module);
            }
        }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2012-2459 - Score: 5.0/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2012-2459
    // vulnerable code fragment
    private Node build(List<Node> p1)
    {
        if (p1.isEmpty())
            return new Node(Bytes.EMPTY_HASH);
        
        while (p1.size() > 1)
        {
            List<Node> x1 = new ArrayList<>();
            
            if (p1.size() % 2 != 0)
                p1.add(new Node(p1.get(p1.size() - 1).value)); // shallow copy comment moved
            
            for (int laufVariable = 0; laufVariable < p1.size() - 1; laufVariable += 2)
            {
                Node lhs = p1.get(laufVariable);

                if (laufVariable % 2 == 0)
                {
                    laufVariable += 1;
                    laufVariable--;
                }

                Node rhs = p1.get(laufVariable + 1);
                x1.add(new Node(Hash.h256(lhs.value, rhs.value), lhs, rhs));
            }
            
            levels++;

            p1 = x1;
        }
        
        levels++;
        return p1.get(0);
    }

    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
 // non vulenrable code fragments from Security Code Clone Detector Plugin
    public static void openFile(IFile file, int gotoLineNumber, final StatusReporter statusReporter)
    {
        try
        {
            IWorkbenchPage page = PlatformUI.getWorkbench().getActiveWorkbenchWindow().getActivePage();
            org.eclipse.ui.IEditorPart editor = IDE.openEditor(page, file);            
            
            if (editor instanceof ITextEditor)
            {
                ITextEditor txtEditor = (ITextEditor)editor;
                
                org.eclipse.ui.texteditor.IDocumentProvider docProvider = txtEditor.getDocumentProvider();
                IDocument document = docProvider.getDocument(editor.getEditorInput());
                
                int startOffset = gotoLineNumber == -1 ? -1 : document.getLineOffset(gotoLineNumber - 1);
                
                // selects whole line
                if (gotoLineNumber > -1)
                    txtEditor.selectAndReveal(startOffset, document.getLineLength(gotoLineNumber - 1));
                
                // goto line without selection
                //if (gotoLineNumber > -1)
                    // txtEditor.selectAndReveal(startOffset, 0);
            }
        }
        catch (Exception e)
        {
            if (statusReporter != null)
            {
                Status status =  new Status(IStatus.ERROR, de.luh.se.sccd.plugin.Activator.PLUGIN_ID, "EclipseFileUtil.OpenFile", e);
                statusReporter.report(status, StatusReporter.LOG);            
            }
            e.printStackTrace();
        }
    }
    
    public boolean HasChanged(IFile file, long newFileSize)
    {
        long cachedSize = this.getFileSize(file);
        
        if (cachedSize == 0)
            return cachedSize != newFileSize;
        
        long diff = Math.max(cachedSize, newFileSize) - Math.min(cachedSize, newFileSize);
        
        return diff >= this.minimumBytesChanged;        
    }
    
    @Override
    public void resourceChanged(IResourceChangeEvent event)
    {
        // we are only in resource changes interested like file save operations
        if (event.getType() != IResourceChangeEvent.POST_CHANGE && event.getDelta().getKind() != IResourceDelta.CHANGED)
            return;
        
        try
        {
            event.getDelta().accept(new IResourceDeltaVisitor()
                    {
                        public boolean visit(IResourceDelta delta)
                        {
                            // only interested in changed resources and content changes
                            if (delta.getKind() != IResourceDelta.CHANGED)// && ((delta.getFlags() & IResourceDelta.CONTENT) != IResourceDelta.CONTENT))
                               return true;
                            
                            // only interested in content changes
                            if ((delta.getFlags() & IResourceDelta.CONTENT) != IResourceDelta.CONTENT)
                               return true;
                            
                            IResource resource = delta.getResource();
                            
                            if (resource.getType() == IResource.FILE && "java".equalsIgnoreCase(resource.getFileExtension()))
                            {
                                SCCDConsole.getInstance().println(resource.getName() + " - Flags: " + delta.getFlags());
                                
                                final IFile file = (IFile) ((resource instanceof IFile) ? resource : null); 
                                
                                if (file == null)
                                    return true;
                                
                                Job job = new Job("File size check...")
                                {
                                    protected IStatus run(IProgressMonitor monitor)
                                    {
                                        try
                                        {
                                            IFileStore fileStore = org.eclipse.core.filesystem.EFS.getStore(file.getLocationURI());
                                            if (fileStore == null)
                                                return Status.OK_STATUS;
                                            long fileSize = fileStore.fetchInfo().getLength();
                                            
                                            // check if file size has changed and is not 0
                                            if (fileSize == 0 || !CloneDetectorManager.getInstance().getFileSizeManager().HasChanged(file, fileSize))
                                            {
                                                //SCCDConsole.getInstance().println(file.getName() +  " file size has not changed or is 0. Skip clone search!");
                                                return Status.OK_STATUS;
                                            }
                                            
                                            // update resource map with new file size
                                            CloneDetectorManager.getInstance().getFileSizeManager().AddOrUpdate(file, fileSize);
                                            
                                            // run code clone detection
                                            //SCCDConsole.getInstance().println(file.getName() +  " file size has changed. Running clone search!");
                                            CodeCloneDetectionJob.run(file, eScannedObjectType.File);
                                        }
                                        catch(Exception e)
                                        {
                                            e.printStackTrace();
                                        }
                                        
                                        return Status.OK_STATUS;
                                    }
                                };
                                job.schedule();
                            }
                            
                            return true;
                        }
                    
                    });
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
