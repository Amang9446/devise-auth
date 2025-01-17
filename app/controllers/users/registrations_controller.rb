class Users::RegistrationsController < Devise::RegistrationsController
  include RackSessionFix
  before_action :configure_sign_up_params, only: [:create]
  respond_to :json
  private

  def respond_with(resource, _opts = {})
    if request.method == "POST" && resource.persisted?
      render json: {
         message: "Signed up sucessfully.",
        data: resource  
      }, status: :ok
    elsif request.method == "DELETE"
      render json: {
         message: "Account deleted successfully.",
      }, status: :ok
    else
      render json: {
        message: "User couldn't be created successfully.",
        errors: resource.errors.full_messages.to_sentence
      }, status: :unprocessable_entity
    end
  end

  protected

  def configure_sign_up_params
    devise_parameter_sanitizer.permit(:sign_up, keys: [:username, :email, :password])
  end

end
