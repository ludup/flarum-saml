import { extend, override } from 'flarum/extend';
import app from 'flarum/app';
import SettingsPage from "flarum/components/SettingsPage";
import SignUpModal from "flarum/components/SignUpModal";
import LogInButton from 'flarum/components/LogInButton';
import LogInButtons from 'flarum/components/LogInButtons';
import LogInModal from "flarum/components/LogInModal";

app.initializers.add('askvortsov/saml', () => {
    override(LogInModal.prototype, 'body', dontShowLoginModalIfOnlySaml);
    override(SignUpModal.prototype, 'body', dontShowSignupModalIfOnlySaml);
    extend(LogInButtons.prototype, 'items', addSamlLoginButton);

    extend(SettingsPage.prototype, 'accountItems', removeProfileActions);
    extend(SettingsPage.prototype, 'settingsItems', checkRemoveAccountSection);

    function dontShowLoginModalIfOnlySaml() {
        if (app.forum.attribute('onlyUseSaml')) {
            return app.translator.trans('askvortsov-saml.forum.log_in.see_popup_to_login');
        } else {
            return [
                <LogInButtons />,

                <div className="Form Form--centered">
                    {this.fields().toArray()}
                </div>
            ];
        }
    }

    function dontShowSignupModalIfOnlySaml() {
        if (app.forum.attribute('onlyUseSaml') && (jQuery.isEmptyObject(this.props) || this.props.username == "" && this.props.password == "")) {
            return app.translator.trans('askvortsov-saml.forum.log_in.see_popup_to_register');
        } else {
            console.log(this.props);
            return [
                this.props.token ? '' : <LogInButtons />,

                <div className="Form Form--centered">
                    {this.fields().toArray()}
                </div>
            ];
        }
    }

    function addSamlLoginButton(items) {
        items.add('saml',
            <LogInButton
                className="Button LogInButton--saml"
                icon="fas fa-lock"
                path="/auth/saml/login">
                {app.translator.trans('askvortsov-saml.forum.log_in.with_saml_button')}
            </LogInButton>
        );
    };

    function removeProfileActions(items) {
        items.remove('changeEmail');
        items.remove('changePassword');
    }
    function checkRemoveAccountSection(items) {
        if (items.has('account') &&
            items.get('account').props.children.length === 0) {
            items.remove('account');
        }
    }
});

$(function () {
    $('.item-logIn>button').add('.item-signUp>button').on("click", function (e) {
        if (app.forum.attribute('onlyUseSaml')) {
            var win = window.open("/auth/saml/login", "_blank", "height=500,width=600,resizable=no,toolbar=no,menubar=no,location=no,status=no")
            if (win == null) {
                win == window.open("/auth/saml/login", "_blank")
            }
            if (win == null) {
                alert(app.translator.trans('askvortsov-saml.forum.log_in.enable_popups'))
            }
            win.focus();
        }
    });
});