import type { APIRoute } from 'astro';

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();
    const { username, password } = body;

    if (!username || !password) {
      return new Response(JSON.stringify({ 
        message: 'Username and password are required' 
      }), {
        status: 400,
        headers: {
          'Content-Type': 'application/json'
        }
      });
    }

    const backendUrl = import.meta.env.BACKEND_URL;
    
    if (!backendUrl) {
      return new Response(JSON.stringify({ 
        message: 'Backend URL not configured' 
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json'
        }
      });
    }

    // Forward the request to the backend
    const response = await fetch(`${backendUrl}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    });

    const data = await response.json();

    if (response.ok) {
      return new Response(JSON.stringify({ 
        message: 'Login successful',
        data: data 
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json'
        }
      });
    } else {
      return new Response(JSON.stringify({ 
        message: data.message || 'Login failed' 
      }), {
        status: response.status,
        headers: {
          'Content-Type': 'application/json'
        }
      });
    }
  } catch (error) {
    console.error('Login API error:', error);
    return new Response(JSON.stringify({ 
      message: 'An error occurred. Please try again.' 
    }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json'
      }
    });
  }
};
