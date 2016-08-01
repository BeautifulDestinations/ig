{-# LANGUAGE FlexibleContexts #-}
-- | handle the authorization mecanism for Instagram
-- <http://instagram.com/developer/authentication/#>
module Instagram.Auth (
  RedirectUri,
  getUserAccessTokenURL1,
  getUserAccessTokenURL2
) where

import Instagram.Monad
import Instagram.Types

import Data.Text hiding (map)
import Control.Monad (liftM)
import Control.Monad.IO.Class (liftIO)

import qualified Data.ByteString as BS (ByteString,intercalate)
import qualified Data.Text.Encoding as TE
import qualified Network.HTTP.Types as HT


-- | the URI to redirect the user after she accepts/refuses to authorize the app
type RedirectUri = Text

-- | get the authorize url to redirect your user to
getUserAccessTokenURL1 :: (MonadBaseControl IO m, MonadResource m) =>
  RedirectUri -- ^ the URI to redirect the user after she accepts/refuses to authorize the app
  -> [Scope] -- ^ the requested scopes (can be empty for Basic)
  -> InstagramT m Text -- ^ the URL to redirect the user to
getUserAccessTokenURL1 url scopes=  do  
  cid<-liftM clientIDBS getCreds
  let q = buildQuery cid ++ buildScopes scopes
  liftIO $ print q  
  bsurl<-getQueryURL "/oauth/authorize/" q
  return $ TE.decodeUtf8 bsurl
  where
    -- | build the query with client id and redirect URI
    buildQuery :: BS.ByteString -> HT.SimpleQuery
    buildQuery cid=[("client_id",cid),("redirect_uri",TE.encodeUtf8 url),("response_type","code")]
    buildScopes ::  [Scope] ->  HT.SimpleQuery
    buildScopes []=[]
    buildScopes l =[("scope",BS.intercalate "+" $ map (TE.encodeUtf8 . pack . show) l)]

-- | second step of authorization: get the access token once the user has been redirected with a code
getUserAccessTokenURL2 :: (MonadBaseControl IO m, MonadResource m) =>
  RedirectUri -- ^ the redirect uri
  -> Text -- ^ the code sent back to your app
  -> InstagramT m OAuthToken -- ^ the auth token
getUserAccessTokenURL2 url code= do
  cid<-liftM clientIDBS getCreds
  csecret<-liftM clientSecretBS getCreds
  let q = buildQuery cid csecret
  liftIO $ putStrLn $ "getUserAccessTokenURL2: q = " ++ show q
  q2 <- addClientInfos q
  liftIO $ putStrLn $ "getUserAccessTokenURL2: q2 = " ++ show q2
  (return q2) >>= getPostRequest "/oauth/access_token" >>= getJSONResponse
  where
    -- | build query parameters
    buildQuery ::  BS.ByteString -> BS.ByteString -> HT.SimpleQuery
    buildQuery cid csecret = [("client_id",cid),("client_secret",csecret),("grant_type","authorization_code"),
                              ("redirect_uri",TE.encodeUtf8 url),("code",TE.encodeUtf8 code)]
