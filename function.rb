# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # event: Hash

  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html


  #################   ----- Legitimacy Check -----   #################

  # Requests to any other resources must respond with status code 404.
  validPath = ['/token', '/']
  if !validPath.include?(event['path']) then
    return response(status: 404)
  end

  # Requests to / or /token which do not use the appropriate HTTP method must respond with status code 405.
  if (event['path'] == '/' && event['httpMethod'] != 'GET')||(event['path'] == '/token' && event['httpMethod'] != 'POST') then
    return response(status: 405)
  end


  #################   ----- Main -----   #################
  if event['httpMethod'] == 'GET' then
    if event['path'] == '/' then
      begin
        auth = event['headers']['Authorization']
      rescue
        # Responds 403 if a proper Authorization: Bearer <TOKEN> header is not provided.
        return response(status: 403)
      end
      # Responds 403 if a proper Authorization: Bearer <TOKEN> header is not provided.
      if auth[0..6] != 'Bearer ' then
        return response(status: 403)
      end
      token = auth[7..-1]
      begin
        decoded_token = JWT.decode token, ENV['JWT_SECRET'], true, { algorithm: 'HS256' }
        # puts "decoded: #{decoded_token.class}\n #{decoded_token}"
        payload = decoded_token[0]['data']
        return response(body: payload, status: 200)
      rescue# JWT::ExpiredSignature, JWT::ImmatureSignature, JWT::InvalidIssuerError
        # Responds 401 if either the token is not yet valid, or if it is expired.
        return response(status: 401)
      end
    else
      # Requests to any other resources must respond with status code 404.
      return response(status: 404)
    end
  elsif event['httpMethod'] == 'POST' then
    if event['path'] == '/token' then
      # Responds 415 if the request content type is not application/json.
      if event['headers']['Content-Type'] != 'application/json' then
        return response(status: 415)
      end
      begin
        bodyData = JSON.parse(event['body'])  # Body: Hash
        # generate a payload
        payload = {
          data: bodyData,
          exp: Time.now.to_i + 5,
          nbf: Time.now.to_i + 2
        }
        token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
        return response(body: {token: token}, status: 201)
      rescue
        # Responds 422 if the body of the request is not actually json.
        return response(status: 422)
      end
    else
      # Requests to any other resources must respond with status code 404.
      return response(status: 404)
    end
  else
    # inappropriate HTTP method must respond with status code 405.
    return response(status: 405)
  end

end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
