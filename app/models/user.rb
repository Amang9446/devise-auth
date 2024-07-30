class User < ApplicationRecord
  include Devise::JWT::RevocationStrategies::JTIMatcher

  attr_writer :login

  def login
    @login || self.username || self.email
  end

  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :jwt_authenticatable, jwt_revocation_strategy: self,
         authentication_keys: [:login]

  validates :username, presence: true, uniqueness: true
  validates :email, presence: true, uniqueness: true

  def self.find_for_database_authentication(warden_conditions)
    conditions = warden_conditions.dup
    if login = conditions.delete(:login)
      where(conditions.to_h).where(["lower(username) = :value OR lower(email) = :value", { value: login.downcase }]).first
    elsif conditions.has_key?(:username) || conditions.has_key?(:email)
      where(conditions.to_h).first
    end
  end
end
