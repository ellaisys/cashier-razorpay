<?php

/*
 * This file is part of Cashier Razorpay package.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ellaisys\Cashier\Providers;

use Ellaisys\Cashier\AwsCognito;
use Ellaisys\Cashier\AwsCognitoClient;
use Ellaisys\Cashier\AwsCognitoManager;

use Ellaisys\Cashier\Http\Parser\Parser;
use Ellaisys\Cashier\Http\Parser\AuthHeaders;

use Ellaisys\Cashier\Providers\StorageProvider;

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;


/**
 * Class CashierServiceProvider.
 */
class CashierServiceProvider extends ServiceProvider
{
    
    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        //Register Alias
        $this->registerAliases();
    } //Function ends


    public function boot()
    {
        //Configuration path
        $path = realpath(__DIR__.'/../../config/cashier.php');

        //Publish config
        $this->publishes([
            $path => $this->app->config_path('cashier.php'),
        ], 'cashier-config');

        //Register configuration
        $this->mergeConfigFrom($path, 'cashier');

        // $this->registerPolicies();

        // //Register facades
        // $this->registerCognitoFacades();

        // //Set Singleton Class
        // $this->registerCognitoProvider();

        // //Set Guards
        // $this->extendWebAuthGuard();
        // $this->extendApiAuthGuard();
    } //Function ends


    /**
     * Bind some aliases.
     *
     * @return void
     */
    protected function registerAliases()
    {
        //$this->app->alias('ellaisys.aws.cognito', AwsCognito::class);
    }


    /**
     * Register Cashier Facades
     *
     * @return void
     */
    protected function registerCognitoFacades()
    {
        //Request Parser
        $this->app->singleton('ellaisys.aws.cognito.parser', function (Application $app) {
            $parser = new Parser(
                $app['request'],
                [
                    new AuthHeaders,
                    // new QueryString,
                    // new InputSource,
                    // new RouteParams,
                    // new Cookies($this->config('decrypt_cookies')),
                ]
            );

            $app->refresh('request', $parser, 'setRequest');

            return $parser;
        });

        //Storage Provider
        $this->app->singleton('ellaisys.aws.cognito.provider.storage', function (Application $app) {
            return (new StorageProvider(
                config('cognito.storage_provider')
            ));
        });

        //Aws Cashier Manager
        $this->app->singleton('ellaisys.aws.cognito.manager', function (Application $app) {
            return (new AwsCognitoManager(
                $app['ellaisys.aws.cognito.provider.storage']
            ));
        });

        $this->app->singleton('ellaisys.aws.cognito', function (Application $app, array $config) {
            return (new AwsCognito(
                $app['ellaisys.aws.cognito.manager'],
                $app['ellaisys.aws.cognito.parser']
            ));
        });
    } //Function ends


    /**
     * Register Cashier Provider
     *
     * @return void
     */
    protected function registerCognitoProvider()
    {
        $this->app->singleton(AwsCognitoClient::class, function (Application $app) {
            $aws_config = [
                'region'      => config('cognito.region'),
                'version'     => config('cognito.version')
            ];

            //Set AWS Credentials
            $credentials = config('cognito.credentials');
            if (! empty($credentials['key']) && ! empty($credentials['secret'])) {
                $aws_config['credentials'] = Arr::only($credentials, ['key', 'secret', 'token']);
            } //End if

            return new AwsCognitoClient(
                new CognitoIdentityProviderClient($aws_config),
                config('cognito.app_client_id'),
                config('cognito.app_client_secret'),
                config('cognito.user_pool_id')
            );
        });
    } //Function ends


    /**
     * Extend Cashier Web/Session Auth.
     *
     * @return void
     */
    protected function extendWebAuthGuard()
    {
        Auth::extend('cognito-session', function (Application $app, $name, array $config) {
            $guard = new CognitoSessionGuard(
                $name,
                $client = $app->make(AwsCognitoClient::class),
                $app['auth']->createUserProvider($config['provider']),
                $app['session.store'],
                $app['request']
            );

            $guard->setCookieJar($this->app['cookie']);
            $guard->setDispatcher($this->app['events']);
            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));

            return $guard;
        });
    } //Function ends


    /**
     * Extend Cashier Api Auth.
     *
     * @return void
     */
    protected function extendApiAuthGuard()
    {
        Auth::extend('cognito-token', function (Application $app, $name, array $config) {

            $guard = new CognitoTokenGuard(
                $app['ellaisys.aws.cognito'],
                $client = $app->make(AwsCognitoClient::class),
                $app['request'],
                Auth::createUserProvider($config['provider'])
            );

            $guard->setRequest($app->refresh('request', $guard, 'setRequest'));

            return $guard;
        });
    } //Function ends
    
} //Class ends