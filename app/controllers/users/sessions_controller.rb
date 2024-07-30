class Users::SessionsController < Devise::SessionsController
  include RackSessionFix
  before_action :configure_sign_in_params, only: [:create]
  respond_to :json
  private

  def respond_with(resource, _opts = {})
    render json: {
       message: 'Logged in sucessfully.',
      data: resource
    }, status: :ok
  end

  def respond_to_on_destroy
    if current_user
      render json: {
        message: "logged out successfully"
      }, status: :ok
    else
      render json: {
        message: "Couldn't find an active session."
      }, status: :unauthorized
    end
  end

  protected

  def configure_sign_in_params
    devise_parameter_sanitizer.permit(:sign_in, keys: [:login, :password])
  end
end
