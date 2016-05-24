<?php

$PluginInfo['loginThrottle'] = [
    'Name' => 'Login Throttle',
    'Description' => 'Prevent brute force attacks.',
    'Version' => '0.1',
    'RequiredApplications' => array('Vanilla' => '>= 2.2'),
    'RequiredTheme' => false,
    'SettingsPermission' => ['Garden.Settings.Manage'],
    'SettingsUrl' => '/dashboard/settings/loginthrottle',
    'MobileFriendly' => true,
    'HasLocale' => true,
    'Author' => 'Robin Jurinka',
    'AuthorUrl' => 'http://vanillaforums.org/profile/44046/R_J',
    'License' => 'MIT'
];


/**
 * Prevent brute force attacks on user accounts.
 *
 * This is inspired by businessdads LoginGuard plugin.
 * No code is re-used from the original plugin, only settings named are copied.
 */
class LoginThrottlePlugin extends Gdn_Plugin {

    public function settingsController_loginThrottle_create($sender) {
        $sender->permission('Garden.Settings.Manage');
        $sender->addSideMenu('dashboard/settings/plugins');
        $sender->setData('Title', t('Login Throttle Settings'));

        $configurationModule = new ConfigurationModule($sender);

        $configurationModule->initialize(
            [
                'loginThrottle.AttemptsLimit' => [
                    'Default' => 3,
                    'Label' => 'Login attempts limit',
                    'Description' => 'Number of wrong login attempts a user can make before his account gets suspended',
                    'Options' => [
                        'class' => 'InputBox BigInput',
                        'type' => 'number'
                    ]
                ],
                'loginThrottle.DelayFirst' => [
                    'Default' => 2,
                    'Label' => 'Delay after first wrong login tries',
                    'Description' => 'Specify minutes a user has to wait until he can try to log into his account again.',
                    'Options' => [
                        'class' => 'InputBox BigInput',
                        'type' => 'number'
                    ]
                ],
                'loginThrottle.DelayConsecutive' => [
                    'Default' => 3,
                    'Label' => 'Delay for consecutive wrong logins',
                    'Description' => 'The amount of time an account is suspended when a user continuously enters a wrong password.',
                    'Options' => [
                        'class' => 'InputBox BigInput',
                        'type' => 'number'
                    ]
                ]
            ]
        );
        $configurationModule->renderAll();
    }

    public function entryController_render_before($sender, $args) {
        // Only check when values have been posted to signin.
        if (
            $sender->OriginalRequestMethod != 'signin' ||
            !$sender->Request->isPostBack()
        ) {
            return;
        }

        // Get user.
        $email = $sender->Form->getValue('Email');
        $user = Gdn::userModel()->getByEmail($email);
        if (!$user) {
            $user = Gdn::userModel()->getByUsername($email);
        }
        if (!$user) {
            // Return if user name does not exist.
            return;
        }

        // Get throttle information of the current user.
        $throttleInfo = $this->getThrottleInfo($user->UserID);

        $date = new DateTime();

        if ($throttleInfo['ReleaseTime'] > $date->getTimestamp()) {
            // If user is currently suspended, fail with custom error message.
            $sender->Form->addError(
                sprintf(
                    t('Too many failed login attempts.'),
                    $throttleInfo['ReleaseTime']
                )
            );
            return;
        }

        // If current login failed, update throttle information.
        $validationResults = $sender->Form->validationResults();
        if (
            isset($validationResults['<General Error>']) &&
            in_array('Invalid password.', $validationResults['<General Error>'])
        ) {
            $throttleInfo = $this->updateThrottleInfo($user->UserID);

            $this->setThrottleInfo($user->UserID, $throttleInfo);

            // Show remaining attempts to user.
            $attemptsRemaining = c('loginThrottle.AttemptsLimit') - $throttleInfo['FailedAttemptsCount'];
            if (
                $attemptsRemaining > 0 &&
                $throttleInfo['ReleaseTime'] <= $date->getTimestamp()
            ) {
                $sender->Form->addError(
                    sprintf(
                        t('You have %s tries left.'),
                        c('loginThrottle.AttemptsLimit') - $throttleInfo['FailedAttemptsCount']
                    )
                );
            } else {
                $suspensionPeriod = max(
                    $throttleInfo['SuspensionPeriod'],
                    c('loginThrottle.DelayFirst')
                );
                $sender->Form->addError(
                    sprintf(
                        t('Your account has been suspended for %u minutes.'),
                        $suspensionPeriod
                    )
                );
            }
        }

    }

    /**
     * Reset info about failed attempts when user successfully logs in.
     *
     * @param userModel $sender The calling model.
     * @param mixed $args Event arguments.
     * @return void.
     */
    public function userModel_afterSignIn_handler($sender, $args) {
        $this->setThrottleInfo($args['UserID'], [], 'loginThrottle.');
    }

    /**
     * Fetch throttle information from user meta table.
     *
     * @param integer $userID The user for which the info must be fetched.
     * @return mixed Throttle information.
     */
    protected function getThrottleInfo($userID) {
        $throttleInfo = Gdn::userModel()->getMeta(
            $userID,
            'loginThrottle.%',
            'loginThrottle.'
        );

        $throttleInfo['FailedAttemptsCount'] = val(
            'FailedAttemptsCount',
            $throttleInfo,
            0
        );
        $throttleInfo['SuspensionPeriod'] = val(
            'SuspensionPeriod',
            $throttleInfo,
            0
        );
        $throttleInfo['ReleaseTime'] = val(
            'ReleaseTime',
            $throttleInfo,
            0
        );

        return $throttleInfo;
    }

    /**
     * Write throttle info to user meta table.
     *
     * @param integer $userID The user for which the info must be set.
     * @param array $throttleInfo The information to write.
     * @return array $throttleInfo.
     */
    protected function setThrottleInfo($userID, $throttleInfo = []) {
        $throttleInfo['FailedAttemptsCount'] = val(
            'FailedAttemptsCount',
            $throttleInfo,
            null
        );
        $throttleInfo['SuspensionPeriod'] = val(
            'SuspensionPeriod',
            $throttleInfo,
            null
        );
        $throttleInfo['ReleaseTime'] = val(
            'ReleaseTime',
            $throttleInfo,
            null
        );

        Gdn::userModel()->setMeta($userID, $throttleInfo, 'loginThrottle.');

        return $throttleInfo;
    }

    /**
     * Update throttle info after wrong sign in.
     *
     * @param integer $userID The id of the user who tried to sign in.
     * @return mixed $throttleInfo Updated throttle info.
     */
    protected function updateThrottleInfo($userID) {
        $throttleInfo = $this->getThrottleInfo($userID);

        // Increase failed attempts count.
        $throttleInfo['FailedAttemptsCount']++;

        // Initiate blocking if limit is exceeded.
        if ($throttleInfo['FailedAttemptsCount'] > c('loginThrottle.AttemptsLimit')) {
            // Set period for blocking based on previous period.
            if ($throttleInfo['SuspensionPeriod'] == 0) {
                $throttleInfo['SuspensionPeriod'] = c('loginThrottle.DelayFirst');
            } else {
                $throttleInfo['SuspensionPeriod'] += c('loginThrottle.DelayConsecutive');
            }

            // Calculate new unblocking time.
            $date = new DateTime();
            $date->modify(sprintf('+%u minutes', $throttleInfo['SuspensionPeriod']));
            $throttleInfo['ReleaseTime'] = $date->getTimestamp();
            $throttleInfo['FailedAttemptsCount'] = 0;
        }

        return $throttleInfo;
    }
}
