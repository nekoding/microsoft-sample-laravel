<?php
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\TokenStore\TokenCache;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Microsoft\Graph\Graph;
use Microsoft\Graph\Model;

class AuthController extends Controller
{
  public function signin()
  {
    // Initialize the OAuth client
    $oauthClient = new \League\OAuth2\Client\Provider\GenericProvider([
      'clientId'                => config('azure.appId'),
      'clientSecret'            => config('azure.appSecret'),
      'redirectUri'             => config('azure.redirectUri'),
      'urlAuthorize'            => config('azure.authority') . config('azure.authorizeEndpoint'),
      'urlAccessToken'          => config('azure.authority') . config('azure.tokenEndpoint'),
      'urlResourceOwnerDetails' => '',
      'scopes'                  => config('azure.scopes')
    ]);

    $authUrl = $oauthClient->getAuthorizationUrl();

    // Save client state so we can validate in callback
    session(['oauthState' => $oauthClient->getState()]);

    // Redirect to AAD signin page
    return redirect()->away($authUrl);
  }

  public function callback(Request $request)
  {
    // Validate state
    $expectedState = session('oauthState');
    $request->session()->forget('oauthState');
    $providedState = $request->query('state');

    if (!isset($expectedState)) {
      // If there is no expected state in the session,
      // do nothing and redirect to the home page.
      return redirect('/');
    }

    if (!isset($providedState) || $expectedState != $providedState) {
      return redirect('/')
        ->with('error', 'Invalid auth state')
        ->with('errorDetail', 'The provided auth state did not match the expected value');
    }

    // Authorization code should be in the "code" query param
    $authCode = $request->query('code');
    if (isset($authCode)) {
      // Initialize the OAuth client
      $oauthClient = new \League\OAuth2\Client\Provider\GenericProvider([
        'clientId'                => config('azure.appId'),
        'clientSecret'            => config('azure.appSecret'),
        'redirectUri'             => config('azure.redirectUri'),
        'urlAuthorize'            => config('azure.authority') . config('azure.authorizeEndpoint'),
        'urlAccessToken'          => config('azure.authority') . config('azure.tokenEndpoint'),
        'urlResourceOwnerDetails' => '',
        'scopes'                  => config('azure.scopes')
      ]);

      try {
        // Make the token request
        $accessToken = $oauthClient->getAccessToken('authorization_code', [
          'code' => $authCode
        ]);

        $graph = new Graph();
        $graph->setAccessToken($accessToken->getToken());

        $user = $graph->createRequest('GET', '/me?$select=displayName,mail,mailboxSettings,userPrincipalName')
          ->setReturnType(Model\User::class)
          ->execute();

        // $user = $graph->createRequest('GET', '/me?$select=displayName,mail,userPrincipalName')
        //   ->setReturnType(Model\User::class)
        //   ->execute();

        $tokenCache = new TokenCache();
        $tokenCache->storeTokens($accessToken, $user);

        return redirect('/');
      } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
        return redirect('/')
          ->with('error', 'Error requesting access token')
          ->with('errorDetail', json_encode($e->getResponseBody()));
      }
    }

    return redirect('/')
      ->with('error', $request->query('error'))
      ->with('errorDetail', $request->query('error_description'));
  }

  public function signout()
  {
    $tokenCache = new TokenCache();
    $tokenCache->clearTokens();
    return redirect('/');
  }

  public function refreshToken()
  {

    $refreshToken = session()->get('refreshToken');

    if (!$refreshToken) {
      return redirect()->to('/signout');
    }

    $response = Http::asForm()->post("https://login.microsoftonline.com/common/oauth2/v2.0/token", [
      'client_id'     => config('azure.appId'),
      'scope'         => config('azure.scopes'),
      'refresh_token' => $refreshToken,
      'grant_type'    => 'refresh_token',
      'client_secret' => config('azure.appSecret'),
    ]);

    // redirect to login page again if fail
    if ($response->status() != 200) {
      return redirect()->to('/signout');
    }

    $result = $response->json();

    // update access token
    session([
      'accessToken' => $result['access_token'],
      'refreshToken' => $result['refresh_token'],
      'tokenExpires' => Carbon::createFromTimestamp(session()->get('tokenExpires'))->addSeconds($result['expires_in'])->timestamp
    ]);

    return redirect()->to('/calendar');
  }
}
