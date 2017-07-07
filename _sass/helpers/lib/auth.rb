require "jwt"

class Auth
  ALGORITHM = "HS256"

  def self.issue(payload, expiry=24.hours.from_now)
    payload[:exp] = expiry.to_i
    JWT.encode(payload, auth_secret, ALGORITHM)
  end

  def self.decode(token, leeway=0)
    decoded = JWT.decode(token, auth_secret, true, { leeway: leeway, algorithm: ALGORITHM })
    HashWithIndifferentAccess.new(decoded[0])
  end

  def self.auth_secret
    ENV["AUTH_SECRET"]
  end
end
